(ns ipso.memory
  "Memory Layer for ipso-agent:
   - COT1 Protocol implementation (OP_RETURN AI memory logs)
   - BRC-78 Encrypted Blobs using AES-256-GCM
   - SHIP/SLAP Agent Discovery on-chain registry"
  (:require [cheshire.core :as json]
            [ipso.identity :as ident]
            [bsv.rpc.client :as rpc]
            [bsv.rpc.transaction :as tx]
            [clojure.tools.logging :as log])
  (:import [java.security SecureRandom MessageDigest]
           [java.util Arrays Base64 UUID HexFormat]
           [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec GCMParameterSpec]))

;; ── BRC-78 Encryption (AES-256-GCM) ──

(defn derive-aes-key
  "Derives a 256-bit AES key from WIF key string by hashing it."
  [^String wif]
  (let [md (MessageDigest/getInstance "SHA-256")
        key-bytes (.digest md (.getBytes wif "UTF-8"))]
    (SecretKeySpec. key-bytes "AES")))

(defn encrypt-blob
  "Encrypts a string plaintext with AES-256-GCM.
   Returns a Base64 string containing [IV (12B)][Ciphertext + GCM Tag]."
  [^String plaintext ^String wif]
  (let [key (derive-aes-key wif)
        iv (byte-array 12)
        _ (.nextBytes (SecureRandom.) iv)
        cipher (Cipher/getInstance "AES/GCM/NoPadding")
        spec (GCMParameterSpec. 128 iv)
        _ (.init cipher Cipher/ENCRYPT_MODE key spec)
        ciphertext (.doFinal cipher (.getBytes plaintext "UTF-8"))
        combined (byte-array (+ 12 (alength ciphertext)))]
    (System/arraycopy iv 0 combined 0 12)
    (System/arraycopy ciphertext 0 combined 12 (alength ciphertext))
    (.encodeToString (Base64/getEncoder) combined)))

(defn decrypt-blob
  "Decrypts a GCM Base64-encoded encrypted blob.
   Returns plaintext string."
  [^String ciphertext-b64 ^String wif]
  (let [key (derive-aes-key wif)
        combined (.decode (Base64/getDecoder) ciphertext-b64)
        iv (Arrays/copyOfRange combined 0 12)
        ciphertext (Arrays/copyOfRange combined 12 (alength combined))
        cipher (Cipher/getInstance "AES/GCM/NoPadding")
        spec (GCMParameterSpec. 128 iv)
        _ (.init cipher Cipher/DECRYPT_MODE key spec)
        plaintext-bytes (.doFinal cipher ciphertext)]
    (String. plaintext-bytes "UTF-8")))

;; ── COT1 Protocol (Memory Serialization) ──

(defn build-cot1-payload
  "Builds a COT1 payload string: COT1|<agent-cga>|<type>|<data-blob>"
  [agent-cga type data-blob]
  (str "COT1|" agent-cga "|" (name type) "|" data-blob))

(defn build-cot1-transaction
  "Constructs a COT1 memory transaction.
   If WIF is provided, encrypts the data under BRC-78 first.
   Parameters:
     - agent-wif: Agent's WIF key
     - type: :conversation, :state, or :reputation
     - data-str: Plaintext data string
     - inputs: UTXOs to spend
     - change-address: Change destination"
  [agent-wif type data-str inputs change-address]
  (let [pubkey (ident/derive-identity agent-wif)
        cga (ident/derive-cga-ipv6 pubkey)
        encrypted-blob (encrypt-blob data-str agent-wif)
        cot1-data (build-cot1-payload cga type encrypted-blob)
        op-return-script (str "6a" (.formatHex (HexFormat/of) (.getBytes cot1-data "UTF-8")))
        txid (let [md (MessageDigest/getInstance "SHA-256")
                   hash-bytes (.digest md (.getBytes cot1-data "UTF-8"))]
               (.formatHex (HexFormat/of) hash-bytes))]
    {:txid txid
     :op-return cot1-data
     :script-hex op-return-script
     :type :cot1
     :cga cga}))

;; ── SHIP/SLAP Agent Discovery ──

(defn create-ship-advertisement
  "Creates a signed SHIP/SLAP advertisement map.
   Parameters:
     - agent-name: Agent name
     - wif: Agent's WIF key
     - services: vector of service name keywords e.g. [:payment :clob]
     - endpoint: P2P or HTTP network endpoint string"
  [agent-name wif services endpoint]
  (let [pubkey (ident/derive-identity wif)
        cga (ident/derive-cga-ipv6 pubkey)
        timestamp (System/currentTimeMillis)
        services-str (clojure.string/join "," (map clojure.core/name services))
        payload (str agent-name "|" cga "|" services-str "|" endpoint "|" timestamp)
        signature (ident/sign-data payload wif)]
    {:name agent-name
     :cga cga
     :services services
     :endpoint endpoint
     :timestamp timestamp
     :signature signature}))

(defn build-ship-transaction
  "Creates a transaction map containing the SHIP advertisement script."
  [adv-map]
  (let [serialized (json/generate-string adv-map)
        payload (str "SHIP|" serialized)
        op-return-script (str "6a" (.formatHex (HexFormat/of) (.getBytes payload "UTF-8")))
        txid (let [md (MessageDigest/getInstance "SHA-256")
                   hash-bytes (.digest md (.getBytes payload "UTF-8"))]
               (.formatHex (HexFormat/of) hash-bytes))]
    {:txid txid
     :op-return payload
     :script-hex op-return-script
     :type :ship}))

(defn parse-ship-advertisement
  "Parses and verifies a SHIP advertisement string."
  [op-return-data pubkey]
  (try
    (when (.startsWith op-return-data "SHIP|")
      (let [json-str (subs op-return-data 5)
            adv (json/parse-string json-str keyword)
            services-str (clojure.string/join "," (map name (:services adv)))
            payload (str (:name adv) "|" (:cga adv) "|" services-str "|" (:endpoint adv) "|" (:timestamp adv))
            verified? (ident/verify-data-signature payload (:signature adv) pubkey)]
        (assoc adv :verified? verified?)))
    (catch Exception e
      (log/warn "Failed to parse SHIP advertisement:" (.getMessage e))
      nil)))
