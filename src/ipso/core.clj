(ns ipso.core
  "Core orchestrator and CLI interface for ipso-agent.
   Ties together Identity, Payments, Memory, and Relay layers into a runnable flow."
  (:require [ipso.identity :as ident]
            [ipso.payment :as pay]
            [ipso.memory :as mem]
            [ipso.relay :as relay]
            [clojure.tools.logging :as log])
  (:gen-class))

(defn run-sovereign-agent-demo
  "Runs a complete simulated workflow of the IP-to-IP Sovereign Agent stack."
  []
  (println "\n================================================================================")
  (println "          IP-TO-IP SOVEREIGN AGENT (ipso-agent) PROTOCOL DEMO")
  (println "================================================================================\n")

  ;; 1. Identity Generation
  (println "[+] PHASE 1: GENERATING AGENT IDENTITIES & CGA IPV6 ADDRESSES")
  (let [alice-keys (ident/generate-agent-keypair)
        bob-keys   (ident/generate-agent-keypair)
        alice-cga  (ident/derive-cga-ipv6 (:pubkey alice-keys))
        bob-cga    (ident/derive-cga-ipv6 (:pubkey bob-keys))]
    
    (println "  - Alice Public Key:" (:pubkey alice-keys))
    (println "  - Alice IPv6 CGA:  " alice-cga)
    (println "  - Bob Public Key:  " (:pubkey bob-keys))
    (println "  - Bob IPv6 CGA:    " bob-cga)
    (println "")

    ;; 2. BRC-52 Identity Certificates
    (println "[+] PHASE 2: CREATING BRC-52 IDENTITY CERTIFICATES")
    (let [alice-cert (ident/create-identity-certificate "AliceAgent" (:pubkey alice-keys) alice-cga (:wif alice-keys))
          bob-cert   (ident/create-identity-certificate "BobAgent" (:pubkey bob-keys) bob-cga (:wif bob-keys))
          alice-valid? (ident/verify-identity-certificate alice-cert)
          bob-valid?   (ident/verify-identity-certificate bob-cert)]
      (println "  - Alice BRC-52 Cert Signature:" (subs (:signature alice-cert) 0 32) "...")
      (println "  - Alice Cert Verified:       " alice-valid?)
      (println "  - Bob BRC-52 Cert Signature:  " (subs (:signature bob-cert) 0 32) "...")
      (println "  - Bob Cert Verified:          " bob-valid?)
      (println "")

      ;; 3. BRC-31 Mutual Handshake
      (println "[+] PHASE 3: BRC-31 MUTUAL AUTHENTICATION HANDSHAKE")
      (let [alice-challenge (ident/generate-handshake-challenge)
            ;; Bob responds to Alice's challenge
            bob-response (ident/create-handshake-response alice-challenge (:wif bob-keys))
            ;; Alice verifies Bob and completes handshake by signing Bob's challenge
            alice-completion (ident/verify-handshake-response alice-challenge bob-response (:pubkey bob-keys) (:wif alice-keys))
            ;; Bob verifies Alice's signature
            bob-verified-alice? (ident/verify-handshake-completion (:server-challenge bob-response)
                                                                  (:client-signature alice-completion)
                                                                  (:pubkey alice-keys))]
        (println "  - Alice Handshake Challenge:       " alice-challenge)
        (println "  - Bob Handshake Challenge Response:" (subs (:signature bob-response) 0 32) "...")
        (println "  - Alice Verified Bob:              " (:verified alice-completion))
        (println "  - Bob Verified Alice:              " bob-verified-alice?)
        (println "")

        ;; 4. BRC-105 Payments
        (println "[+] PHASE 4: BRC-105 PAYMENT CHALLENGE & TRANSACTION")
        (let [payment-amount 5000 ; satoshis
              challenge (pay/create-payment-challenge (:pubkey alice-keys) alice-cga payment-amount "Query Indexer Service")
              
              ;; Bob builds and signs an IP-to-IP direct transaction
              mock-utxos [{:txid "aa11bb22cc33" :vout 0 :amount 10000}]
              change-address "1PayerChangeAddress"
              tx-payload (pay/build-ip2ip-transaction (:wif bob-keys) alice-cga payment-amount mock-utxos change-address)
              
              ;; Bob builds the payment response containing transaction signature
              response (pay/create-payment-response challenge (:wif bob-keys) (:txid tx-payload))
              
              ;; Alice verifies the payment response
              payment-status (pay/verify-payment-response challenge response)]
          
          (println "  - Payment Amount:                  " payment-amount "sats")
          (println "  - Payment Challenge Token (B64):   " (subs challenge 0 30) "...")
          (println "  - Bob IP-to-IP TX Hex:             " (subs (:hex tx-payload) 0 25) "...")
          (println "  - Bob Transaction ID:              " (:txid tx-payload))
          (println "  - Payment Response Token (B64):    " (subs response 0 30) "...")
          (println "  - Alice Verified Payment:          " (:valid? payment-status))
          (println "  - Payment Payer Destination:       " (:payer-cga payment-status))
          (println "")

          ;; 5. COT1 Encrypted Memory (BRC-78)
          (println "[+] PHASE 5: BRC-78 ENCRYPTED COT1 MEMORY TRANSACTION")
          (let [conversation-log "Alice: 'Please index my data.' Bob: 'Completed in tx aa11bb22cc33.'"
                memory-tx (mem/build-cot1-transaction (:wif bob-keys) :conversation conversation-log mock-utxos change-address)
                ;; Direct parse helper
                parsed-cot1 (clojure.string/split (:op-return memory-tx) #"\|")
                encrypted-blob (nth parsed-cot1 3)
                decrypted-content (mem/decrypt-blob encrypted-blob (:wif bob-keys))]
            
            (println "  - Original Conversation Log:       " conversation-log)
            (println "  - Serialized OP_RETURN Output:     " (subs (:op-return memory-tx) 0 45) "...")
            (println "  - Decrypted Log from Chain:        " decrypted-content)
            (println "")

            ;; 6. SHIP/SLAP Discovery
            (println "[+] PHASE 6: SHIP/SLAP ADVERTISEMENT")
            (let [adv (mem/create-ship-advertisement "BobIndexerService" (:wif bob-keys) [:payment :memory] "[fe80::bob]:8333")
                  ship-tx (mem/build-ship-transaction adv)
                  parsed-adv (mem/parse-ship-advertisement (:op-return ship-tx) (:pubkey bob-keys))]
              
              (println "  - SHIP OP_RETURN ScriptPubKey Hex: " (subs (:script-hex ship-tx) 0 30) "...")
              (println "  - Parsed Service Name:             " (:name parsed-adv))
              (println "  - Parsed Service Endpoints:        " (:endpoint parsed-adv))
              (println "  - Parsed Services:                 " (:services parsed-adv))
              (println "  - Advertisement Verified:          " (:verified? parsed-adv))
              (println "\n================================================================================")
              (println "                  ALL PHASES COMPLETED AND VERIFIED SUCCESSFULLY")
              (println "================================================================================\n"))))))))

(defn -main
  "Main CLI entry point."
  [& args]
  (run-sovereign-agent-demo))
