package ws

type hub struct {
	// Registered clients.
	clients map[*client]string

	// Register requests from the clients.
	register chan *client

	// Unregister requests from clients.
	unregister chan *client

	// Inbound messages from the clients.
	broadcast chan *message
}

func newHub() *hub {
	return &hub{
		clients:    make(map[*client]string),
		register:   make(chan *client),
		unregister: make(chan *client),
		broadcast:  make(chan *message),
	}
}

func (h *hub) run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = ""

		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}

		case message := <-h.broadcast:
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
		}
	}
}
