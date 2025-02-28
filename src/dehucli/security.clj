(ns dehucli.security
  (:require [clojure.java.io :as io])
  (:import [javax.security.auth.callback Callback CallbackHandler]
           [org.apache.wss4j.common.ext WSPasswordCallback]
           [java.security KeyStore]
           [java.security.cert CertificateFactory X509Certificate]
           [java.io FileInputStream]))

;; Password callback class for WS-Security
(defn create-password-callback [keystore-password]
  (reify CallbackHandler
    (handle [this callbacks]
      (doseq [callback callbacks]
        (when (instance? WSPasswordCallback callback)
          (let [cb ^WSPasswordCallback callback]
            ;; Set the password for the private key
            (.setPassword cb keystore-password)))))))

(defn load-certificate 
  "Load an X.509 certificate from a file"
  [cert-file]
  (with-open [is (io/input-stream cert-file)]
    (let [cf (CertificateFactory/getInstance "X.509")]
      (.generateCertificate cf is))))

(defn load-private-key 
  "Load a private key from a file"
  [key-file password]
  (let [ks (KeyStore/getInstance "PKCS12")]
    (with-open [is (FileInputStream. key-file)]
      (.load ks is (char-array password))
      (let [aliases (enumeration-seq (.aliases ks))
            alias (first aliases)]
        (.getKey ks alias (char-array password))))))

(defn initialize-keystore 
  "Initialize a keystore with the certificate and private key"
  [cert-file key-file password]
  (let [cert (load-certificate cert-file)
        key (load-private-key key-file password)
        ks (KeyStore/getInstance "JKS")]
    (.load ks nil nil)
    (.setKeyEntry ks "dehu-key" key (char-array password) (into-array X509Certificate [cert]))
    ks))

;; Create properties file for WS-Security
(defn create-crypto-properties [cert-file key-file password]
  (let [props (java.util.Properties.)]
    (doto props
      (.setProperty "org.apache.wss4j.crypto.provider" 
                   "org.apache.wss4j.common.crypto.Merlin")
      (.setProperty "org.apache.wss4j.crypto.merlin.keystore.type" "JKS")
      (.setProperty "org.apache.wss4j.crypto.merlin.keystore.password" password)
      (.setProperty "org.apache.wss4j.crypto.merlin.keystore.alias" "dehu-key"))
    
    ;; Save properties to a file
    (with-open [out (io/output-stream "crypto.properties")]
      (.store props out "WSS4J Crypto properties"))
    
    ;; Return the keystore
    (initialize-keystore cert-file key-file password)))