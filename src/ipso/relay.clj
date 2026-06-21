(ns ipso.relay
  "Relay and Mesh Routing Layer for ipso-agent:
   - Registers active agent routes (CGA to callbacks)
   - Dispatches agent-to-agent messages
   - Simulates P2P message relay over the federated mesh"
  (:require [clojure.tools.logging :as log]))

;; In-memory route table mapping CGA to handler callback functions
(defonce ^:private route-table (atom {}))

(defn register-agent-route!
  "Registers a message callback handler for a given agent CGA address."
  [cga handler-fn]
  (swap! route-table assoc cga handler-fn)
  (log/info "Agent registered on relay mesh:" cga))

(defn unregister-agent-route!
  "Removes an agent route from the table."
  [cga]
  (swap! route-table dissoc cga)
  (log/info "Agent unregistered from relay mesh:" cga))

(defn send-agent-message
  "Sends a message from sender-cga to receiver-cga over the simulated P2P mesh.
   Returns true if message was delivered, false if destination was unreachable."
  [sender-cga receiver-cga message-type payload]
  (if-let [handler (get @route-table receiver-cga)]
    (try
      ;; Deliver asynchronously to simulate network latency
      (future
        (handler {:sender sender-cga
                  :type message-type
                  :payload payload}))
      true
      (catch Exception e
        (log/error e "Error delivering message to" receiver-cga)
        false))
    (do
      (log/warn "Route not found on mesh for receiver CGA:" receiver-cga)
      false)))

(defn active-routes
  "Returns list of all active CGA addresses registered on the mesh."
  []
  (keys @route-table))
