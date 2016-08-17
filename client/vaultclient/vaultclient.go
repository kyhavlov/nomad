package vaultclient

import (
	"container/heap"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/hashicorp/nomad/nomad/structs/config"
	vaultapi "github.com/hashicorp/vault/api"
	vaultduration "github.com/hashicorp/vault/helper/duration"
)

// The interface which nomad client uses to interact with vault.
type VaultClient interface {
	// Starts the run loop for renewals of tokens and secrets
	Start()

	// Stops the run loop for renewals of tokens and secrets
	Stop()

	// Contacts the nomad server and fetches a wrapped token. This token
	// will then be unwrapped by contacting vault.
	DeriveToken() (string, error)

	// Fetch the Consul ACL token required for the task
	GetConsulACL(string, string) (*vaultapi.Secret, error)

	// Renew the supplied token and add the token to the min-heap for
	// periodic renewals.
	RenewToken(string) <-chan error

	// Removes the token from the min-heap, stopping its renewal.
	StopRenewToken(string) error

	// Renew a secret's lease and add the lease to the min-heap for
	// periodic renewals.
	RenewLease(string, int) <-chan error

	// Removes a secret's lease id from the min-heap, stopping its renewal.
	StopRenewLease(string) error
}

// Implementation of VaultClient interface to interact with vault and perform
// token and lease renewals periodically.
type vaultClient struct {
	// Indicates if the renewal run-loop is active or not
	running bool

	// Client's vault token
	token string

	// TTL to be set for tokens created by the client
	taskTokenTTL string

	// API client to interact with vault
	vaultAPIClient *vaultapi.Client

	// Channel to notify modifications to the heap
	updateCh chan struct{}

	// Channel to trigger termination of renewal loop
	stopCh chan struct{}

	// Min-Heap to keep track of both tokens and leases
	heap *vaultClientHeap

	lock   sync.RWMutex
	logger *log.Logger
}

// Request object for renewals. This can be used for both token renewals and
// secret's lease renewals.
type vaultClientRenewalRequest struct {
	// Channel into which any renewal error will be sent down to
	errCh chan error

	// This can either be a token or a lease identifier
	id string

	// Duration for which the token or lease should be renewed for
	duration int

	// Indicates whether the 'id' field is a token or not
	isToken bool
}

// Element representing an entry in the renewal heap
type vaultClientHeapEntry struct {
	req   *vaultClientRenewalRequest
	next  time.Time
	index int
}

// Wrapper around the actual heap to provide additional symantics on top of
// functions provided by the heap interface. In order to achieve that, an
// additional map is placed beside the actual heap. This map can be used to
// check if an entry is already present in the heap.
type vaultClientHeap struct {
	heapMap map[string]*vaultClientHeapEntry
	heap    vaultDataHeapImp
}

// Data type of the heap
type vaultDataHeapImp []*vaultClientHeapEntry

// NewVaultClient returns a new vault client from the given config.
func NewVaultClient(vaultConfig *config.VaultConfig, logger *log.Logger) (*vaultClient, error) {
	if vaultConfig == nil {
		return nil, fmt.Errorf("nil vault config")
	}

	// Creation of a vault client requires that the token is supplied via
	// config.
	if vaultConfig.Token == "" {
		return nil, fmt.Errorf("vault token not set")
	}

	if vaultConfig.TaskTokenTTL == "" {
		return nil, fmt.Errorf("task_token_ttl not set")
	}

	if logger == nil {
		return nil, fmt.Errorf("nil logger")
	}

	return &vaultClient{
		token:        vaultConfig.Token,
		taskTokenTTL: vaultConfig.TaskTokenTTL,
		stopCh:       make(chan struct{}),
		updateCh:     make(chan struct{}, 1),
		heap:         NewVaultClientHeap(),
		logger:       logger,
	}, nil
}

// NewVaultClientHeap returns a new vault client heap with both the heap and a
// map which is a secondary index for heap elements, both initialized.
func NewVaultClientHeap() *vaultClientHeap {
	return &vaultClientHeap{
		heapMap: make(map[string]*vaultClientHeapEntry),
		heap:    make(vaultDataHeapImp, 0),
	}
}

// IsTracked returns if a given identifier is already present in the heap and
// hence is being renewed.
func (c *vaultClient) IsTracked(id string) bool {
	if id == "" {
		return false
	}

	_, ok := c.heap.heapMap[id]
	return ok
}

// Starts the renewal loop of vault client
func (c *vaultClient) Start() {
	log.Printf("vaultclient: Started========================***=================================")
	c.lock.Lock()
	c.running = true
	c.lock.Unlock()

	// TODO: Test code begins
	derivedWrappedToken, err := c.DeriveToken()
	if err != nil {
		log.Printf("vaultclient: failed to derive a vault token: %v", err)
	}
	c.RenewToken(derivedWrappedToken)
	// TODO: Test code ends

	go c.run()
}

// Stops the renewal loop of vault client
func (c *vaultClient) Stop() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.running = false
	close(c.stopCh)
}

// DeriveToken contacts the nomad server and fetches a wrapped token. Then it
// contacts vault to unwrap the token and returns the unwrapped token.
func (c *vaultClient) DeriveToken() (string, error) {
	// TODO: Replace this code with an actual call to the nomad server.
	// This is a sample code which directly fetches a wrapped token from
	// vault and unwraps it for time being.
	tcr := &vaultapi.TokenCreateRequest{
		ID:          "vault-token-123",
		Policies:    []string{"foo", "bar"},
		TTL:         "10s",
		DisplayName: "derived-token",
		Renewable:   new(bool),
	}
	*tcr.Renewable = true

	// Create a vault API client
	client, err := c.getVaultAPIClient()
	if err != nil {
		return "", fmt.Errorf("failed to create vault API client: %v", err)
	}

	// Set the TTL for the wrapped token
	wrapLookupFunc := func(method, path string) string {
		if method == "POST" && path == "auth/token/create" {
			return "60s"
		}
		return ""
	}
	client.SetWrappingLookupFunc(wrapLookupFunc)

	// Create a wrapped token
	secret, err := client.Auth().Token().Create(tcr)
	if err != nil {
		return "", fmt.Errorf("failed to create vault token: %v", err)
	}
	if secret == nil || secret.WrapInfo == nil || secret.WrapInfo.Token == "" ||
		secret.WrapInfo.WrappedAccessor == "" {
		return "", fmt.Errorf("failed to derive a wrapped vault token")
	}

	wrappedToken := secret.WrapInfo.Token

	// Unwrap the vault token
	unwrapResp, err := client.Logical().Unwrap(wrappedToken)
	if err != nil {
		return "", fmt.Errorf("failed to unwrap the token: %v", err)
	}
	if unwrapResp == nil || unwrapResp.Auth == nil || unwrapResp.Auth.ClientToken == "" {
		return "", fmt.Errorf("failed to unwrap the token")
	}

	// Return the unwrapped token
	return unwrapResp.Auth.ClientToken, nil
}

// GetConsulACL creates a vault API client and reads from vault a consul ACL
// token used by the task.
func (c *vaultClient) GetConsulACL(token, vaultPath string) (*vaultapi.Secret, error) {
	if token == "" {
		return nil, fmt.Errorf("missing token")
	}
	if vaultPath == "" {
		return nil, fmt.Errorf("missing vault path")
	}

	client, err := c.getVaultAPIClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create vault API client: %v", err)
	}
	// Use the token supplied to interact with vault
	client.SetToken(token)

	// Read the consul ACL token and return the secret directly
	return client.Logical().Read(vaultPath)
}

// RenewToken renews the supplied token and adds it to the min-heap so that it
// is renewed periodically by the renewal loop. Any error returned during
// renewal will be written to a buffered channel and the channel is returned
// instead of an actual error. This helps the caller be notified of a renewal
// failure asynchronously for appropriate actions to be taken.
func (c *vaultClient) RenewToken(token string) <-chan error {
	// Create a buffered error channel
	errCh := make(chan error, 1)

	if token == "" {
		errCh <- fmt.Errorf("missing token")
		return errCh
	}

	// Determine the increment to be used for the renewal based on the
	// configured task_token_ttl.
	increment, err := vaultduration.ParseDurationSecond(c.taskTokenTTL)
	if err != nil {
		errCh <- fmt.Errorf("failed to parse task_token_ttl:%v", err)
		return errCh
	}

	// Convert increment to seconds
	increment /= time.Second

	// Create a renewal request and indicate that the identifier in the
	// request is a token and not a lease
	renewalReq := &vaultClientRenewalRequest{
		errCh:    errCh,
		id:       token,
		isToken:  true,
		duration: int(increment),
	}

	// Perform the renewal of the token and send any error to the dedicated
	// error channel.
	if err := c.renew(renewalReq); err != nil {
		errCh <- err
	}

	return errCh
}

// RenewLease renews the supplied lease identifier for a supplied duration and
// adds it to the min-heap so that it gets renewed periodically by the renewal
// loop. Any error returned during renewal will be written to a buffered
// channel and the channel is returned instead of an actual error. This helps
// the caller be notified of a renewal failure asynchronously for appropriate
// actions to be taken.
func (c *vaultClient) RenewLease(leaseId string, leaseDuration int) <-chan error {
	// Create a buffered error channel
	errCh := make(chan error, 1)

	if leaseId == "" {
		errCh <- fmt.Errorf("missing lease ID")
		return errCh
	}

	if leaseDuration == 0 {
		errCh <- fmt.Errorf("missing lease duration")
		return errCh
	}

	// Create a renewal request using the supplied lease and duration
	renewalReq := &vaultClientRenewalRequest{
		errCh:    make(chan error, 1),
		id:       leaseId,
		duration: leaseDuration,
	}

	// Renew the secret and send any error to the dedicated error channel
	if err := c.renew(renewalReq); err != nil {
		errCh <- err
	}

	return errCh
}

// renew is a common method to handle renewal of both tokens and secret leases.
// It creates a vault API client and invokes either a token renewal request or
// a secret renewal request. If renewal is successful, min-heap is updated
// based on the duration after which it needs its renewal again. The duration
// is set to half the lease duration present in the renewal response.
func (c *vaultClient) renew(req *vaultClientRenewalRequest) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if req == nil {
		return fmt.Errorf("nil renewal request")
	}
	if req.id == "" {
		return fmt.Errorf("missing id in renewal request")
	}

	// Create a vault API client
	client, err := c.getVaultAPIClient()
	if err != nil {
		errCh <- fmt.Errorf("failed to lookup the vault token: %v", err)
		return errCh
	}
	if lookupResp == nil || lookupResp.Data == nil {
		errCh <- fmt.Errorf("failed to lookup the vault token: %v", err)
		return errCh
	}

	var duration time.Duration
	if req.isToken {
		// Renew the token
		renewResp, err := client.Auth().Token().Renew(req.id, req.duration)
		if err != nil {
			return fmt.Errorf("failed to renew the vault token: %v", err)
		}
		if renewResp == nil || renewResp.Auth == nil {
			return fmt.Errorf("failed to renew the vault token")
		}

		// Set the next renewal time to half the lease duration
		duration = time.Duration(renewResp.Auth.LeaseDuration) * time.Second / 2
	} else {
		// Renew the secret
		renewResp, err := client.Sys().Renew(req.id, req.duration)
		if err != nil {
			return fmt.Errorf("failed to renew vault secret: %v", err)
		}
		if renewResp == nil {
			return fmt.Errorf("failed to renew vault secret")
		}

		// Set the next renewal time to half the lease duration
		duration = time.Duration(renewResp.LeaseDuration) * time.Second / 2
	}

	// Determine the next renewal time
	next := time.Now().Add(duration)

	if c.IsTracked(req.id) {
		// If the identifier is already tracked, this indicates a
		// subsequest renewal. In this case, update the existing
		// element in the heap with the new renewal time.

		// There is no need to signal an update for the renewal loop
		// here because this case is hit from the renewal loop itself.
		if err := c.heap.Update(req, next); err != nil {
			return fmt.Errorf("failed to update heap entry. err: %v", err)
		}
	} else {
		// If the identifier is not already tracked, this is a first
		// renewal request. In this case, add an entry into the heap
		// with the next renewal time.
		if err := c.heap.Push(req, next); err != nil {
			return fmt.Errorf("failed to push an entry to heap.  err: %v", err)
		}

		// Signal an update for the renewal loop to trigger a fresh
		// computation for the next best candidate for renewal.
		if c.running {
			select {
			case c.updateCh <- struct{}{}:
			default:
			}
		}
	}

	return nil
}

// run is the renewal loop which performs the periodic renewals of both the
// tokens and the secret leases.
func (c *vaultClient) run() {
	var renewalCh <-chan time.Time
	for c.running {
		// Fetches the candidate for next renewal
		renewalReq, renewalTime := c.nextRenewal()
		if renewalTime.IsZero() {
			// If the heap is empty, don't do anything
			renewalCh = nil
		} else {
			now := time.Now()
			if renewalTime.After(now) {
				// Compute the duration after which the item
				// needs renewal and set the renewalCh to fire
				// at that time.
				renewalDuration := renewalTime.Sub(time.Now())
				renewalCh = time.After(renewalDuration)
			} else {
				// If the renewals of multiple items are too
				// close to each other and by the time the
				// renewal is triggered it might be past the
				// current time (by a small margin of course).
				// In which case, fire immediately.
				renewalCh = time.After(0)
			}
		}

		select {
		case <-renewalCh:
			if err := c.renew(renewalReq); err != nil {
				renewalReq.errCh <- err
			}
		case <-c.updateCh:
			continue
		case <-c.stopCh:
			c.logger.Printf("[INFO] vaultClient stopped")
			return
		}
	}
}

// StopRenewToken removes the item from the heap which represents the given
// token.
func (c *vaultClient) StopRenewToken(token string) error {
	return c.stopRenew(token)
}

// StopRenewLease removes the item from the heap which represents the given
// lease identifier.
func (c *vaultClient) StopRenewLease(leaseId string) error {
	return c.stopRenew(leaseId)
}

// stopRenew removes the given identifier from the heap and signals the renewal
// loop to compute the next best candidate for renewal.
func (c *vaultClient) stopRenew(id string) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if !c.IsTracked(id) {
		return nil
	}

	// Remove the identifier from the heap
	if err := c.heap.Remove(id); err != nil {
		return fmt.Errorf("failed to remove heap entry: %v", err)
	}
	// Delete the identifier from the map only after the it is removed from
	// the heap. Heap's remove method relies on the map.
	delete(c.heap.heapMap, id)

	// Signal an update to the renewal loop.
	if c.running {
		select {
		case c.updateCh <- struct{}{}:
		default:
		}
	}

	return nil
}

// nextRenewal returns the root element of the min-heap, which represents the
// next element to be renewed and the time at which the renewal needs to be
// triggered.
func (c *vaultClient) nextRenewal() (*vaultClientRenewalRequest, time.Time) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	if c.heap.Length() == 0 {
		return nil, time.Time{}
	}

	// Fetches the root element in the min-heap
	nextEntry := c.heap.Peek()
	if nextEntry == nil {
		return nil, time.Time{}
	}

	return nextEntry.req, nextEntry.next
}

// getVaultAPIClient creates an API client for interaction with vault. It will
// already have the vault token set.
func (c *vaultClient) getVaultAPIClient() (*vaultapi.Client, error) {
	if c.vaultAPIClient == nil {
		// Get the default configuration
		config := vaultapi.DefaultConfig()

		// Read the environment variables and update the configuration
		if err := config.ReadEnvironment(); err != nil {
			return nil, fmt.Errorf("failed to read the environment: %v", err)
		}

		// Create a Vault API Client
		client, err := vaultapi.NewClient(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create Vault client: %v", err)
		}

		// Set the authentication required
		client.SetToken(c.periodicToken)
		c.vaultAPIClient = client
	}

	return c.vaultAPIClient, nil
}

// The heap interface requires the following methods to be implemented.
// * Push(x interface{}) // add x as element Len()
// * Pop() interface{}   // remove and return element Len() - 1.
// * sort.Interface
//
// sort.Interface comprises of the following methods:
// * Len() int
// * Less(i, j int) bool
// * Swap(i, j int)

// Part of sort.Interface
func (h vaultDataHeapImp) Len() int { return len(h) }

// Part of sort.Interface
func (h vaultDataHeapImp) Less(i, j int) bool {
	// Two zero times should return false.
	// Otherwise, zero is "greater" than any other time.
	// (To sort it at the end of the list.)
	// Sort such that zero times are at the end of the list.
	iZero, jZero := h[i].next.IsZero(), h[j].next.IsZero()
	if iZero && jZero {
		return false
	} else if iZero {
		return false
	} else if jZero {
		return true
	}

	return h[i].next.Before(h[j].next)
}

// Part of sort.Interface
func (h vaultDataHeapImp) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

// Part of heap.Interface
func (h *vaultDataHeapImp) Push(x interface{}) {
	n := len(*h)
	entry := x.(*vaultClientHeapEntry)
	entry.index = n
	*h = append(*h, entry)
}

// Part of heap.Interface
func (h *vaultDataHeapImp) Pop() interface{} {
	old := *h
	n := len(old)
	entry := old[n-1]
	entry.index = -1 // for safety
	*h = old[0 : n-1]
	return entry
}

// Additional helper functions on top of interface methods

// Length returns the number of elements in the heap
func (h *vaultClientHeap) Length() int {
	return len(h.heap)
}

// Returns the root node of the min-heap
func (h *vaultClientHeap) Peek() *vaultClientHeapEntry {
	if len(h.heap) == 0 {
		return nil
	}

	return h.heap[0]
}

// Push adds the secondary index and inserts an item into the heap
func (h *vaultClientHeap) Push(req *vaultClientRenewalRequest, next time.Time) error {
	if req == nil {
		return fmt.Errorf("nil request")
	}

	if _, ok := h.heapMap[req.id]; ok {
		return fmt.Errorf("entry %v already exists", req.id)
	}

	heapEntry := &vaultClientHeapEntry{
		req:  req,
		next: next,
	}
	h.heapMap[req.id] = heapEntry
	heap.Push(&h.heap, heapEntry)
	return nil
}

// Update will modify the existing item in the heap with the new data and the
// time, and fixes the heap.
func (h *vaultClientHeap) Update(req *vaultClientRenewalRequest, next time.Time) error {
	if entry, ok := h.heapMap[req.id]; ok {
		entry.req = req
		entry.next = next
		heap.Fix(&h.heap, entry.index)
		return nil
	}

	return fmt.Errorf("heap doesn't contain %v", req.id)
}

// Remove will remove an identifier from the secondary index and deletes the
// corresponding node from the heap.
func (h *vaultClientHeap) Remove(id string) error {
	if entry, ok := h.heapMap[id]; ok {
		heap.Remove(&h.heap, entry.index)
		delete(h.heapMap, id)
		return nil
	}

	return fmt.Errorf("heap doesn't contain entry for %v", id)
}
