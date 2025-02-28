(ns dehucli.certificate-utils
  (:require [clojure.java.io :as io])
  (:import [java.security KeyFactory KeyStore]
           [java.security.cert CertificateFactory X509Certificate]
           [java.security.spec PKCS8EncodedKeySpec]
           [java.util Base64]
           [javax.security.auth.x500 X500Principal]))

(defn load-certificate 
  "Load an X.509 certificate from a file"
  [cert-file]
  (with-open [is (io/input-stream cert-file)]
    (let [cf (CertificateFactory/getInstance "X.509")]
      (.generateCertificate cf is))))

(defn extract-certificate-info
  "Extract relevant information from an X.509 certificate"
  [cert-file]
  (let [cert (load-certificate cert-file)
        subject (.getSubjectX500Principal cert)
        subject-dn (.getName subject)
        issuer (.getIssuerX500Principal cert)
        issuer-dn (.getName issuer)
        serial (.getSerialNumber cert)
        not-before (.getNotBefore cert)
        not-after (.getNotAfter cert)
        key-usage (try (.getKeyUsage cert) (catch Exception _ nil))
        signature-algo (.getSigAlgName cert)]
    
    ;; Extract NIF from subject DN
    (let [nif-pattern #"SERIALNUMBER=([A-Z0-9]+)"
          nif-matcher (re-find nif-pattern subject-dn)
          nif (when nif-matcher (second nif-matcher))]
      
      {:subject subject-dn
       :issuer issuer-dn
       :serial (str serial)
       :valid-from not-before
       :valid-until not-after
       :key-usage key-usage
       :signature-algo signature-algo
       :nif nif})))

(defn validate-certificate-for-dehu
  "Validate that a certificate is suitable for DEHú service
   Returns a map with :valid? and :reasons keys"
  [cert-file]
  (try
    (let [cert-info (extract-certificate-info cert-file)
          now (java.util.Date.)
          valid-time? (and 
                       (.after now (:valid-from cert-info))
                       (.before now (:valid-until cert-info)))
          ;; DEHú requires digital signature usage
          key-usage (:key-usage cert-info)
          has-digital-signature? (and key-usage (aget key-usage 0))
          
          ;; Compile validation results
          valid? (and valid-time? has-digital-signature?)
          reasons (cond-> []
                   (not valid-time?) (conj "Certificate is not valid at current time")
                   (not has-digital-signature?) (conj "Certificate does not have digital signature capability"))]
      
      {:valid? valid?
       :reasons reasons
       :cert-info cert-info})
    
    (catch Exception e
      {:valid? false
       :reasons [(str "Error validating certificate: " (.getMessage e))]})))

;; Display certificate information in a user-friendly format
(defn display-certificate-info
  "Display certificate information in a user-friendly format"
  [cert-file]
  (try
    (let [cert-info (extract-certificate-info cert-file)
          validation (validate-certificate-for-dehu cert-file)]
      
      (println "Certificate Information:")
      (println "------------------------")
      (println "Subject:" (:subject cert-info))
      (println "Issuer:" (:issuer cert-info))
      (println "Serial Number:" (:serial cert-info))
      (println "Valid From:" (:valid-from cert-info))
      (println "Valid Until:" (:valid-until cert-info))
      (println "NIF:" (or (:nif cert-info) "Not found"))
      (println "Signature Algorithm:" (:signature-algo cert-info))
      (println)
      
      (println "DEHú Validation:")
      (println "----------------")
      (println "Valid for DEHú:" (if (:valid? validation) "Yes" "No"))
      (when-not (:valid? validation)
        (println "Reasons:")
        (doseq [reason (:reasons validation)]
          (println "- " reason))))
    
    (catch Exception e
      (println "Error displaying certificate information:" (.getMessage e))
      (.printStackTrace e))))
