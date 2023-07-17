// minimalist library for serving APIs over nostr relays
package apistr

import (
	"context"
	"errors"
	"log"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
)

// API server over nostr relays modeled after net/http Server
type Server struct {

	// relays where this server listens for requests
	RelayURLs []url.URL

	// server's hex encoded nostr private key
	PrivateKey string

	// function called to handle conversations with clients
	Handler func(ctx context.Context, conversation chan string)

	// Respond to requests at most this far back
	LookBack time.Duration

	cancel context.CancelFunc

	inShutdown atomic.Bool

	mu            sync.RWMutex
	conversations map[string]*conversation
	relayGroup    sync.WaitGroup
}

type conversation struct {
	PubKey       string
	Relays       map[*nostr.Relay]struct{}
	Channel      chan string
	sharedSecret []byte
	mu           sync.Mutex
	seen         map[string]struct{}
}

func (s *Server) PublicKey() string {
	publicKey, err := nostr.GetPublicKey(s.PrivateKey)
	if err != nil {
		panic("unable to derive nostr public key")
	}
	return publicKey
}

func (s *Server) shuttingDown() bool {
	return s.inShutdown.Load()
}

func (s *Server) ListenAndServe() error {
	if s.shuttingDown() {
		return errors.New("server shutdown")
	}
	s.conversations = make(map[string]*conversation, 10)
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	for _, u := range s.RelayURLs {
		s.relayGroup.Add(1)
		go s.listenAndServeRelay(ctx, u)
	}

	s.relayGroup.Wait()
	return nil
}

func (s *Server) listenAndServeRelay(ctx context.Context, u url.URL) {
	defer s.relayGroup.Done()
	timestamp := nostr.Timestamp(time.Now().Unix() - int64(s.LookBack.Seconds()))
	requests_filter := []nostr.Filter{{
		Kinds: []int{nostr.KindEncryptedDirectMessage},
		Tags:  nostr.TagMap{"p": {s.PublicKey()}},
		Since: &timestamp,
	}}

	timer := time.NewTimer(0)
	defer timer.Stop()
	for timeout := time.Second; ; timeout *= 2 {
		select {

		case <-ctx.Done():
			return

		case <-timer.C:
			relay := nostr.NewRelay(ctx, u.String(),
				nostr.WithAuthHandler(func(ctx context.Context, authEvent *nostr.Event) (ok bool) {
					authEvent.Sign(s.PrivateKey)
					return true
				}),
			)
			err := relay.Connect(context.Background())
			if err != nil {
				log.Println(u, "error connecting to relay:", err)
				log.Println(u, "retrying in:", timeout)
				break
			}
			sub, err := relay.Subscribe(ctx, requests_filter)
			if err != nil {
				log.Println(u, "error subscribing to requests:", err)
				break
			}
			timeout = time.Second

			for {
				select {

				case <-ctx.Done():
					return

				case event := <-sub.Events:
					if event == nil {
						log.Println(u, "received nil event")
						break
					}
					conv, ok := s.getConversation(event.PubKey)
					if !ok {
						conv, err = s.addConversation(event.PubKey, relay)
						if err != nil {
							log.Println(u.String(), event.ID, "unable to add conversation", err)
						}
						go s.startConversation(ctx, conv)
					}
					conv.push(relay, event)

					//case <-sub.EndOfStoredEvents:
					//	log.Println(u, "eose received")

				}
			}

		}
		timer.Reset(timeout)
	}
}

func (s *Server) getConversation(pubKey string) (*conversation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	conv, ok := s.conversations[pubKey]
	return conv, ok
}

func (s *Server) addConversation(pubKey string, relay *nostr.Relay) (*conversation, error) {
	ss, err := nip04.ComputeSharedSecret(pubKey, s.PrivateKey)
	if err != nil {
		return nil, err
	}
	conv := &conversation{
		PubKey:       pubKey,
		Relays:       map[*nostr.Relay]struct{}{relay: struct{}{}},
		Channel:      make(chan string),
		seen:         make(map[string]struct{}, 10),
		sharedSecret: ss,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conversations[pubKey] = conv
	return conv, nil
}

func (s *Server) deleteConversation(pubKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conversations, pubKey)
}

func (s *Server) startConversation(ctx context.Context, conv *conversation) {
	defer s.deleteConversation(conv.PubKey)
	c := make(chan string)
	go s.Handler(ctx, c)
	for {
		select {

		case <-ctx.Done():
			return

		case content := <-conv.Channel:
			req, err := nip04.Decrypt(content, conv.sharedSecret)
			if err != nil {
				log.Println(conv.PubKey, "failed while decrypting content", err)
			}
			c <- req

		case resp, ok := <-c:
			if !ok {
				return
			}
			content, err := nip04.Encrypt(resp, conv.sharedSecret)
			if err != nil {
				log.Println(conv.PubKey, "failed while encrypting handler response", err)
			}
			event := nostr.Event{
				CreatedAt: nostr.Now(),
				Kind:      nostr.KindEncryptedDirectMessage,
				Content:   content,
				Tags:      nostr.Tags{nostr.Tag{"p", conv.PubKey}},
			}
			event.Sign(s.PrivateKey)

			for relay := range conv.Relays {
				status, err := relay.Publish(ctx, event)
				if err != nil {
					log.Println(conv.PubKey, relay.URL, "error while publishing", err)
				}
				if status != nostr.PublishStatusSucceeded {
					log.Println(conv.PubKey, relay.URL, "non-success status", status)
				}
			}
		}
	}
}

func (c *conversation) push(relay *nostr.Relay, event *nostr.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Relays[relay] = struct{}{}
	if _, ok := c.seen[event.ID]; !ok {
		c.seen[event.ID] = struct{}{}
		c.Channel <- event.Content
	}
}

func (s *Server) Shutdown() {
	s.inShutdown.Store(true)
	s.cancel()
}
