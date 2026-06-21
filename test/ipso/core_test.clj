(ns ipso.core-test
  "Automated test suite for ipso-agent:
   - Identity Layer tests (CGA, Keypair, BRC-52, BRC-31)
   - Payment Layer tests (BRC-105, IP-to-IP TX)
   - Memory Layer tests (BRC-78 GCM, COT1, SHIP/SLAP)
   - Relay Layer tests"
  (:require [clojure.test :refer [deftest is testing]]
            [ipso.identity :as ident]
            [ipso.payment :as pay]
            [ipso.memory :as mem]
            [ipso.relay :as relay]))

(deftest test-identity-layer
  (testing "Keypair generation & WIF derivation"
    (let [keys (ident/generate-agent-keypair)]
      (is (string? (:wif keys)))
      (is (string? (:pubkey keys)))
      (is (= 66 (count (:pubkey keys)))))) ; compressed secp256k1 pubkey is 33 bytes = 66 hex chars

  (testing "IPv6 CGA address derivation (RFC 3972)"
    (let [keys (ident/generate-agent-keypair)
          cga (ident/derive-cga-ipv6 (:pubkey keys))]
      (is (string? cga))
      (is (= 39 (count cga))) ; formatted IPv6 address has 39 chars (e.g. xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx)
      (is (clojure.string/starts-with? cga "fe80:0000:0000:0000:"))))

  (testing "BRC-52 Identity Certificates"
    (let [keys (ident/generate-agent-keypair)
          cga (ident/derive-cga-ipv6 (:pubkey keys))
          cert (ident/create-identity-certificate "TestAgent" (:pubkey keys) cga (:wif keys))]
      (is (= "TestAgent" (:name cert)))
      (is (ident/verify-identity-certificate cert))))

  (testing "BRC-31 Handshake"
    (let [client-keys (ident/generate-agent-keypair)
          server-keys (ident/generate-agent-keypair)
          challenge (ident/generate-handshake-challenge)
          response (ident/create-handshake-response challenge (:wif server-keys))
          completion (ident/verify-handshake-response challenge response (:pubkey server-keys) (:wif client-keys))
          verified? (ident/verify-handshake-completion (:server-challenge response)
                                                       (:client-signature completion)
                                                       (:pubkey client-keys))]
      (is (:verified completion))
      (is verified?))))

(deftest test-payment-layer
  (testing "BRC-105 Payment Flow"
    (let [payee-keys (ident/generate-agent-keypair)
          payee-cga (ident/derive-cga-ipv6 (:pubkey payee-keys))
          payer-keys (ident/generate-agent-keypair)
          challenge (pay/create-payment-challenge (:pubkey payee-keys) payee-cga 1000 "Query service")
          response (pay/create-payment-response challenge (:wif payer-keys))
          result (pay/verify-payment-response challenge response)]
      (is (:valid? result))
      (is (= 1000 (:amount result)))
      (is (= payee-cga (:payee-cga result)))))

  (testing "IP-to-IP mock transaction"
    (let [payer-keys (ident/generate-agent-keypair)
          payee-keys (ident/generate-agent-keypair)
          payee-cga (ident/derive-cga-ipv6 (:pubkey payee-keys))
          utxos [{:txid "1234" :vout 0 :amount 2000}]
          tx-payload (pay/build-ip2ip-transaction (:wif payer-keys) payee-cga 1500 utxos "1ChangeAddress")
          status (pay/broadcast-ip2ip-transaction tx-payload)]
      (is (= :mock (:type tx-payload)))
      (is (= :peer-accepted (:status status))))))

(deftest test-memory-layer
  (testing "BRC-78 AES-256-GCM encryption & decryption"
    (let [keys (ident/generate-agent-keypair)
          plaintext "Sovereign AI Persistent state memory logs."
          encrypted (mem/encrypt-blob plaintext (:wif keys))
          decrypted (mem/decrypt-blob encrypted (:wif keys))]
      (is (string? encrypted))
      (is (not= plaintext encrypted))
      (is (= plaintext decrypted))))

  (testing "COT1 payload & transaction building"
    (let [keys (ident/generate-agent-keypair)
          cga (ident/derive-cga-ipv6 (:pubkey keys))
          log-str "Step 1: Check balance. Step 2: Pay Bob."
          tx-payload (mem/build-cot1-transaction (:wif keys) :state log-str [] "1ChangeAddress")]
      (is (= cga (:cga tx-payload)))
      (is (clojure.string/starts-with? (:op-return tx-payload) "COT1|"))))

  (testing "SHIP/SLAP service discovery"
    (let [keys (ident/generate-agent-keypair)
          pubkey (:pubkey keys)
          adv (mem/create-ship-advertisement "TestIndexer" (:wif keys) [:payment :memory] "[fe80::1]:8333")
          tx-payload (mem/build-ship-transaction adv)
          parsed (mem/parse-ship-advertisement (:op-return tx-payload) pubkey)]
      (is (= "TestIndexer" (:name parsed)))
      (is (= "[fe80::1]:8333" (:endpoint parsed)))
      (is (:verified? parsed)))))

(deftest test-relay-mesh
  (testing "Simulated CGA-based routing on mesh"
    (let [alice-keys (ident/generate-agent-keypair)
          alice-cga (ident/derive-cga-ipv6 (:pubkey alice-keys))
          bob-keys (ident/generate-agent-keypair)
          bob-cga (ident/derive-cga-ipv6 (:pubkey bob-keys))
          received-msg (atom nil)
          bob-handler (fn [msg] (reset! received-msg msg))]
      
      (relay/register-agent-route! bob-cga bob-handler)
      (let [success? (relay/send-agent-message alice-cga bob-cga :chat "Hello Bob")]
        (is success?)
        ;; Wait for asynchronous delivery
        (Thread/sleep 100)
        (is (= "Hello Bob" (:payload @received-msg)))
        (is (= :chat (:type @received-msg)))
        (is (= alice-cga (:sender @received-msg))))
      (relay/unregister-agent-route! bob-cga))))
