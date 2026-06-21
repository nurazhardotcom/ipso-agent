(ns ipso.payment
  "Payment Layer for ipso-agent:
   - BRC-105 Payment Protocol (HTTP 402 challenge/response)
   - IP-to-IP direct transaction construction & mock broadcast
   - BRC-77 transaction and message signing"
  (:require [cheshire.core :as json]
            [ipso.identity :as ident]
            [bsv.rpc.client :as rpc]
            [bsv.rpc.transaction :as tx]
            [clojure.tools.logging :as log])
  (:import [java.util Base64 UUID]
           [java.security MessageDigest]))

;; ── BRC-105 Payment Protocol ──

(defn create-payment-challenge
  "Generates a Base64-encoded BRC-105 payment challenge.
   Parameters:
     - payee-pubkey: Payee's compressed public key hex string
     - payee-cga: Payee's IPv6 CGA address
     - amount: Amount in satoshis
     - memo: Optional reason string"
  ([payee-pubkey payee-cga amount]
   (create-payment-challenge payee-pubkey payee-cga amount "Sovereign Micropayment"))
  ([payee-pubkey payee-cga amount memo]
   (let [nonce (str (UUID/randomUUID))
         payload {:nonce nonce
                  :payee-pubkey payee-pubkey
                  :payee-cga payee-cga
                  :amount amount
                  :memo memo
                  :timestamp (System/currentTimeMillis)
                  :type "payment-challenge"}
         json-str (json/generate-string payload)
         encoder (Base64/getUrlEncoder)]
     (.encodeToString encoder (.getBytes json-str "UTF-8")))))

(defn create-payment-response
  "Signs a payment challenge and builds a payment response.
   Parameters:
     - challenge-b64: Base64-encoded payment challenge
     - payer-wif: Payer's WIF private key
     - txid: Optional transaction id that satisfies the payment"
  ([challenge-b64 payer-wif]
   (create-payment-response challenge-b64 payer-wif (str (UUID/randomUUID))))
  ([challenge-b64 payer-wif txid]
   (let [decoder (Base64/getUrlDecoder)
         challenge-json (String. (.decode decoder challenge-b64) "UTF-8")
         challenge (json/parse-string challenge-json keyword)
         ;; Sign challenge nonce + txid to authorize payment
         msg-to-sign (str (:nonce challenge) "|" txid)
         signature (ident/sign-data msg-to-sign payer-wif)
         payer-pubkey (ident/derive-identity payer-wif)
         payer-cga (ident/derive-cga-ipv6 payer-pubkey)
         response-payload {:challenge-nonce (:nonce challenge)
                           :txid txid
                           :payer-pubkey payer-pubkey
                           :payer-cga payer-cga
                           :signature signature
                           :timestamp (System/currentTimeMillis)}
         json-str (json/generate-string response-payload)
         encoder (Base64/getUrlEncoder)]
     (.encodeToString encoder (.getBytes json-str "UTF-8")))))

(defn verify-payment-response
  "Verifies a payment response against the original challenge.
   Returns a map with :valid? and status info."
  [challenge-b64 response-b64]
  (try
    (let [decoder (Base64/getUrlDecoder)
          challenge-json (String. (.decode decoder challenge-b64) "UTF-8")
          challenge (json/parse-string challenge-json keyword)
          response-json (String. (.decode decoder response-b64) "UTF-8")
          response (json/parse-string response-json keyword)
          
          ;; Verify nonce match
          nonces-match? (= (:nonce challenge) (:challenge-nonce response))
          
          ;; Verify signature
          msg-to-verify (str (:nonce challenge) "|" (:txid response))
          signature-valid? (ident/verify-data-signature msg-to-verify
                                                        (:signature response)
                                                        (:payer-pubkey response))
          
          ;; Verify payer CGA matches pubkey
          cga-matches? (= (:payer-cga response) (ident/derive-cga-ipv6 (:payer-pubkey response)))]
      (if (and nonces-match? signature-valid? cga-matches?)
        {:valid? true
         :amount (:amount challenge)
         :payee-cga (:payee-cga challenge)
         :payer-cga (:payer-cga response)
         :txid (:txid response)}
        {:valid? false
         :reason "Verification check failed"
         :checks {:nonces-match? nonces-match?
                  :signature-valid? signature-valid?
                  :cga-matches? cga-matches?}}))
    (catch Exception e
      {:valid? false
       :reason (str "Failed to parse or verify response: " (.getMessage e))})))

;; ── IP-to-IP Direct Transaction Builder ──

(defn build-ip2ip-transaction
  "Constructs an IP-to-IP transaction structure.
   Uses BSV RPC if a node is running, otherwise constructs a mock signed transaction structure.
   Parameters:
     - payer-wif: Payer's WIF private key
     - payee-cga: Payee's IPv6 network destination
     - amount-sats: Amount to pay
     - inputs: Vector of UTXO maps {:txid :vout :amount :scriptPubKey}
     - change-address: Payer's change address"
  ([payer-wif payee-cga amount-sats inputs change-address]
   (build-ip2ip-transaction payer-wif payee-cga amount-sats inputs change-address rpc/*default-config*))
  ([payer-wif payee-cga amount-sats inputs change-address config]
   (let [payer-pubkey (ident/derive-identity payer-wif)
         payer-cga (ident/derive-cga-ipv6 payer-pubkey)
         fee 100
         total-input (reduce + 0 (map :amount inputs))
         change-sats (- total-input amount-sats fee)]
     (if (rpc/node-reachable? config)
       ;; Real Node Path
       (try
         (let [payee-address (ident/public-key->address payer-pubkey) ; Mocking real addr routing
               tx-outputs {payee-address (/ amount-sats 100000000.0)
                           change-address (/ change-sats 100000000.0)}
               tx-inputs (mapv (fn [u] {:txid (:txid u) :vout (:vout u)}) inputs)
               raw-tx (rpc/rpc-call config "createrawtransaction" [tx-inputs tx-outputs])
               signed-tx (rpc/rpc-call config "signrawtransactionwithwallet" [raw-tx])]
           {:hex (:hex signed-tx)
            :txid (str (UUID/randomUUID)) ; placeholder for real broadcast txid
            :type :real
            :payee-cga payee-cga
            :payer-cga payer-cga})
         (catch Exception e
           (log/warn "Node transaction building failed, falling back to mock:" (.getMessage e))
           (build-ip2ip-transaction payer-wif payee-cga amount-sats inputs change-address nil)))
       
       ;; Mock Path (Offline / No Node)
       (let [txid (let [md (MessageDigest/getInstance "SHA-256")
                        pre-hash (str payer-wif "|" payee-cga "|" amount-sats)
                        hash-bytes (.digest md (.getBytes pre-hash "UTF-8"))]
                    (.formatHex (java.util.HexFormat/of) hash-bytes))
             ;; Sign the txid under BRC-77
             brc77-sig (ident/sign-data txid payer-wif)]
         {:txid txid
          :hex (str "01000000MOCK" txid)
          :brc77-sig brc77-sig
          :type :mock
          :amount amount-sats
          :payee-cga payee-cga
          :payer-cga payer-cga})))))

(defn broadcast-ip2ip-transaction
  "Broadcasts the transaction payload (real or mock) to the target peer/destination.
   Returns status map."
  [tx-payload]
  (if (= (:type tx-payload) :real)
    ;; Real broadcast path (simulate peer transmission or RPC broadcast)
    (try
      (let [txid (tx/send-raw-transaction (:hex tx-payload))]
        {:status :broadcasted :txid txid :net :bsv})
      (catch Exception _
        {:status :peer-accepted :txid (:txid tx-payload) :net :simulated}))
    ;; Mock path
    {:status :peer-accepted :txid (:txid tx-payload) :net :simulated}))
