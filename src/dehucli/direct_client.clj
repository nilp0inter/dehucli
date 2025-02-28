(ns dehucli.direct-client
  (:require [clojure.string :as str]
            [clojure.java.io :as io]
            [dehucli.ssl :as ssl])
  (:import [org.apache.http.client.methods HttpPost]
           [org.apache.http.entity StringEntity]
           [org.apache.http.impl.client HttpClients]
           [org.apache.http.util EntityUtils]
           [java.time ZonedDateTime ZoneOffset]
           [java.time.format DateTimeFormatter]
           [java.security.cert CertificateFactory X509Certificate]
           [java.security KeyFactory]
           [java.security.spec PKCS8EncodedKeySpec]
           [java.util Base64 Date]
           [java.io StringReader StringWriter]
           [javax.xml.transform TransformerFactory OutputKeys]
           [javax.xml.transform.stream StreamSource StreamResult]
           [org.apache.xml.security Init]
           [org.apache.xml.security.signature XMLSignature]
           [org.apache.xml.security.transforms Transforms]
           [org.apache.xml.security.utils Constants ElementProxy]))

;; Format ISO date for timestamp
(defn format-iso-date []
  (let [now (ZonedDateTime/now ZoneOffset/UTC)
        expires (.plusMinutes now 5)
        formatter (DateTimeFormatter/ofPattern "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")]
    {:created (.format now formatter)
     :expires (.format expires formatter)}))

;; Load certificate as Base64 and get its information
(defn load-certificate-info [cert-file]
  (try
    (with-open [is (io/input-stream cert-file)]
      (let [cf (CertificateFactory/getInstance "X.509")
            cert (.generateCertificate cf is)
            encoded (.getEncoded cert)
            b64 (.encodeToString (java.util.Base64/getEncoder) encoded)
            dn (.getSubjectX500Principal cert)
            dn-name (.getName dn)
            ;; Extract CN from the certificate's distinguished name
            cn (second (re-find #"CN=([^,]+)" dn-name))
            ;; Try to extract NIF from CN (common format is "NAME - NIF")
            nif-from-cn (second (re-find #".*\s+-\s+(\w+)$" cn))
            
            ;; Try to extract NIF from serial number field (OID 2.5.4.5)
            serial-number (second (re-find #"2.5.4.5=#([^,]+)" dn-name))
            
            ;; Get the NIF from serial number if available
            nif-from-serial (when serial-number
                              (try
                                ;; Attempt to decode the hex representation
                                (let [hex-str (if (.startsWith serial-number "130f")
                                               (subs serial-number 4) ;; Remove "130f" prefix
                                               serial-number)
                                      byte-array (for [i (range 0 (count hex-str) 2)]
                                                 (Integer/parseInt (subs hex-str i (+ i 2)) 16))
                                      chars (map char byte-array)
                                      decoded (apply str chars)]
                                  ;; If it starts with "IDCES-", extract the part after it
                                  (if (.startsWith decoded "IDCES-")
                                    (subs decoded 6)
                                    decoded))
                                (catch Exception e
                                  (println "Warning: Could not decode serial number:" e)
                                  nil)))
                                  
            ;; Use the best available NIF source from certificate information
            nif (or nif-from-cn nif-from-serial)]
        
        (println "Certificate subject:" dn-name)
        (println "Common Name (CN):" cn)
        (println "Serial Number:" serial-number)
        (when nif (println "Extracted NIF:" nif))
        
        {:base64 b64
         :cert cert
         :cn cn
         :nif nif}))
    (catch Exception e
      (println "Error loading certificate:" (.getMessage e))
      (.printStackTrace e)
      nil)))

;; Load certificate as Base64 (for backwards compatibility)
(defn load-certificate-as-base64 [cert-file]
  (when-let [cert-info (load-certificate-info cert-file)]
    (:base64 cert-info)))

;; Enhanced version with actual signature
(defn create-soap-envelope
  ([operation params cert-info key-file]
   (create-soap-envelope operation params cert-info key-file
                         "http://administracion.gob.es/punto-unico-notificaciones/localiza"
                         "ns2"))
  
  ([operation params cert-info key-file namespace prefix]
   (try
     (let [timestamp (format-iso-date)
           ;; Create proper capitalized operation name
           op-name (str (Character/toUpperCase (first operation)) (subs operation 1))
           ;; Extract certificate data
           cert-base64 (:base64 cert-info)
           cert (:cert cert-info)
           
           ;; Load private key
           private-key (try
                         (let [key-content (slurp key-file)
                               ;; Extract the content between BEGIN PRIVATE KEY and END PRIVATE KEY
                               begin-marker "-----BEGIN PRIVATE KEY-----"
                               end-marker "-----END PRIVATE KEY-----"
                               begin-idx (str/index-of key-content begin-marker)
                               end-idx (str/index-of key-content end-marker)
                               
                               _ (when (or (nil? begin-idx) (nil? end-idx))
                                   (throw (IllegalArgumentException. 
                                          (str "Cannot find private key markers in the file: " key-file))))
                               
                               ;; Extract just the base64 encoded key (after BEGIN marker, before END marker)
                               key-base64-block (subs key-content 
                                                    (+ begin-idx (count begin-marker))
                                                    end-idx)
                               
                               ;; Remove whitespace and newlines
                               private-key-b64 (-> key-base64-block
                                                 (str/replace #"[\r\n\s]" "")
                                                 (str/trim))
                               
                               ;; Decode and create key
                               decoded-key (.decode (Base64/getDecoder) private-key-b64)
                               key-spec (PKCS8EncodedKeySpec. decoded-key)
                               key-factory (KeyFactory/getInstance "RSA")]
                           
                           (println "Loading private key from:" key-file)
                           (.generatePrivate key-factory key-spec))
                         (catch Exception e
                           (println "Error loading private key:" (.getMessage e))
                           (.printStackTrace e)
                           nil))
           
           ;; Generate random IDs for elements that need to be signed
           ts-id (str "TS-" (java.util.UUID/randomUUID))
           body-id (str "Body-" (java.util.UUID/randomUUID))
           cert-id (str "X509-" (java.util.UUID/randomUUID))
           
           ;; Create XML DOM document for proper signing
           doc-builder-factory (javax.xml.parsers.DocumentBuilderFactory/newInstance)
           _ (.setNamespaceAware doc-builder-factory true)
           doc-builder (.newDocumentBuilder doc-builder-factory)
           doc (.newDocument doc-builder)
           
           ;; Building the envelope manually with DOM to support proper signing
           envelope-element (.createElementNS doc "http://schemas.xmlsoap.org/soap/envelope/" "soapenv:Envelope")
           _ (.appendChild doc envelope-element)
           _ (.setAttributeNS envelope-element "http://www.w3.org/2000/xmlns/" "xmlns:soapenv" "http://schemas.xmlsoap.org/soap/envelope/")
           _ (.setAttributeNS envelope-element "http://www.w3.org/2000/xmlns/" "xmlns:ds" "http://www.w3.org/2000/09/xmldsig#")
           _ (.setAttributeNS envelope-element "http://www.w3.org/2000/xmlns/" "xmlns:wsse" "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
           _ (.setAttributeNS envelope-element "http://www.w3.org/2000/xmlns/" "xmlns:wsu" "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
           
           ;; Create header
           header (.createElementNS doc "http://schemas.xmlsoap.org/soap/envelope/" "soapenv:Header")
           _ (.appendChild envelope-element header)
           
           ;; Create security element
           security (.createElementNS doc "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" "wsse:Security")
           _ (.setAttributeNS security "http://schemas.xmlsoap.org/soap/envelope/" "soapenv:mustUnderstand" "1")
           _ (.appendChild header security)
           
           ;; Create binary security token
           bst (.createElementNS doc "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" "wsse:BinarySecurityToken")
           _ (.setAttributeNS bst "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" "wsu:Id" cert-id)
           _ (.setAttribute bst "EncodingType" "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
           _ (.setAttribute bst "ValueType" "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
           _ (.appendChild bst (.createTextNode doc cert-base64))
           _ (.appendChild security bst)
           
           ;; Create timestamp
           timestamp-el (.createElementNS doc "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" "wsu:Timestamp")
           _ (.setAttributeNS timestamp-el "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" "wsu:Id" ts-id)
           created (.createElementNS doc "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" "wsu:Created")
           _ (.appendChild created (.createTextNode doc (:created timestamp)))
           _ (.appendChild timestamp-el created)
           expires (.createElementNS doc "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" "wsu:Expires")
           _ (.appendChild expires (.createTextNode doc (:expires timestamp)))
           _ (.appendChild timestamp-el expires)
           _ (.appendChild security timestamp-el)
           
           ;; Create body with ID for signing
           body (.createElementNS doc "http://schemas.xmlsoap.org/soap/envelope/" "soapenv:Body")
           _ (.setAttributeNS body "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" "wsu:Id" body-id)
           _ (.appendChild envelope-element body)
           
           ;; Create operation element
           op-element (.createElementNS doc namespace (str prefix ":" op-name))
           _ (.setAttributeNS op-element (str "http://www.w3.org/2000/xmlns/") (str "xmlns:" prefix) namespace)
           _ (.appendChild body op-element)
           
           ;; Add parameters - use the NIF from the certificate, not the Common Name
           nif-element (.createElementNS doc namespace (str prefix ":nifTitular"))
           _ (.appendChild nif-element (.createTextNode doc (:nif cert-info)))
           _ (.appendChild op-element nif-element)
           
           tipo-element (.createElementNS doc namespace (str prefix ":tipoEnvio"))
           _ (.appendChild tipo-element (.createTextNode doc "2"))
           _ (.appendChild op-element tipo-element)
           
           ;; Initialize XML security library
           _ (org.apache.xml.security.Init/init)
           
           ;; Create and add signature per standard example in DEHú spec
           _ (let [;; First create signature element
                   ds-ns "http://www.w3.org/2000/09/xmldsig#"
                   sig-element (.createElementNS doc ds-ns "ds:Signature")
                   ;; Don't add ID to Signature as it might cause validation issues
                   ;; sig-id (str "SIG-" (java.util.UUID/randomUUID))
                   ;; _ (.setAttributeNS sig-element "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" "wsu:Id" sig-id)
                   _ (.appendChild security sig-element)
                   
                   ;; Create SignedInfo element
                   signed-info (.createElementNS doc ds-ns "ds:SignedInfo")
                   _ (.appendChild sig-element signed-info)
                   
                   ;; Add CanonicalizationMethod
                   c14n-method (.createElementNS doc ds-ns "ds:CanonicalizationMethod")
                   _ (.setAttribute c14n-method "Algorithm" "http://www.w3.org/2001/10/xml-exc-c14n#")
                   _ (.appendChild signed-info c14n-method)
                   
                   ;; Create InclusiveNamespaces for CanonicalizationMethod (try with this again)
                   inc-namespaces (.createElementNS doc "http://www.w3.org/2001/10/xml-exc-c14n#" "ec:InclusiveNamespaces")
                   _ (.setAttribute inc-namespaces "PrefixList" (str prefix " soapenv"))
                   _ (.appendChild c14n-method inc-namespaces)
                   
                   ;; From spec: SignatureMethod *must* use SHA-1
                   sig-method (.createElementNS doc ds-ns "ds:SignatureMethod")
                   _ (.setAttribute sig-method "Algorithm" "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
                   _ (.appendChild signed-info sig-method)
                   
                   ;; Add Reference for Timestamp
                   ts-ref (.createElementNS doc ds-ns "ds:Reference")
                   _ (.setAttribute ts-ref "URI" (str "#" ts-id))
                   _ (.appendChild signed-info ts-ref)
                   
                   ;; Add Transforms for Timestamp
                   ts-transforms (.createElementNS doc ds-ns "ds:Transforms")
                   _ (.appendChild ts-ref ts-transforms)
                   ts-transform (.createElementNS doc ds-ns "ds:Transform")
                   _ (.setAttribute ts-transform "Algorithm" "http://www.w3.org/2001/10/xml-exc-c14n#")
                   _ (.appendChild ts-transforms ts-transform)
                   
                   ;; Create InclusiveNamespaces for Transform (try with this again)
                   ts-inc-namespaces (.createElementNS doc "http://www.w3.org/2001/10/xml-exc-c14n#" "ec:InclusiveNamespaces")
                   _ (.setAttribute ts-inc-namespaces "PrefixList" "")
                   _ (.appendChild ts-transform ts-inc-namespaces)
                   
                   ;; Per the spec: DigestMethod MUST be SHA-256 
                   ts-digest-method (.createElementNS doc ds-ns "ds:DigestMethod")
                   _ (.setAttribute ts-digest-method "Algorithm" "http://www.w3.org/2001/04/xmlenc#sha256")
                   _ (.appendChild ts-ref ts-digest-method)
                   
                   ;; Convert timestamp to canonical form for digesting
                   sw-ts (java.io.StringWriter.)
                   _ (-> (javax.xml.transform.TransformerFactory/newInstance)
                        (.newTransformer)
                        (doto (.setOutputProperty OutputKeys/OMIT_XML_DECLARATION "yes"))
                        (.transform (javax.xml.transform.dom.DOMSource. timestamp-el)
                                   (javax.xml.transform.stream.StreamResult. sw-ts)))
                   canonicalized-ts (.toString sw-ts)
                   
                   ;; Compute timestamp digest value (SHA-256)
                   ts-digest-bytes (-> (java.security.MessageDigest/getInstance "SHA-256")
                                     (doto (.update (.getBytes canonicalized-ts "UTF-8")))
                                     (.digest))
                   ts-digest-b64 (.encodeToString (Base64/getEncoder) ts-digest-bytes)
                   
                   ;; Add DigestValue for Timestamp
                   ts-digest-value (.createElementNS doc ds-ns "ds:DigestValue")
                   _ (.appendChild ts-digest-value (.createTextNode doc ts-digest-b64))
                   _ (.appendChild ts-ref ts-digest-value)
                   
                   ;; Add Reference for Body
                   body-ref (.createElementNS doc ds-ns "ds:Reference")
                   _ (.setAttribute body-ref "URI" (str "#" body-id))
                   _ (.appendChild signed-info body-ref)
                   
                   ;; Add Transforms for Body
                   body-transforms (.createElementNS doc ds-ns "ds:Transforms")
                   _ (.appendChild body-ref body-transforms)
                   body-transform (.createElementNS doc ds-ns "ds:Transform")
                   _ (.setAttribute body-transform "Algorithm" "http://www.w3.org/2001/10/xml-exc-c14n#")
                   _ (.appendChild body-transforms body-transform)
                   
                   ;; Create InclusiveNamespaces for Body Transform (try with this again)
                   body-inc-namespaces (.createElementNS doc "http://www.w3.org/2001/10/xml-exc-c14n#" "ec:InclusiveNamespaces")
                   _ (.setAttribute body-inc-namespaces "PrefixList" prefix) 
                   _ (.appendChild body-transform body-inc-namespaces)
                   
                   ;; Per the spec: DigestMethod MUST be SHA-256
                   body-digest-method (.createElementNS doc ds-ns "ds:DigestMethod")
                   _ (.setAttribute body-digest-method "Algorithm" "http://www.w3.org/2001/04/xmlenc#sha256")
                   _ (.appendChild body-ref body-digest-method)
                   
                   ;; Convert body to canonical form for digesting
                   sw-body (java.io.StringWriter.)
                   _ (-> (javax.xml.transform.TransformerFactory/newInstance)
                        (.newTransformer)
                        (doto (.setOutputProperty OutputKeys/OMIT_XML_DECLARATION "yes"))
                        (.transform (javax.xml.transform.dom.DOMSource. body)
                                   (javax.xml.transform.stream.StreamResult. sw-body)))
                   canonicalized-body (.toString sw-body)
                   
                   ;; Compute body digest value (SHA-256)
                   body-digest-bytes (-> (java.security.MessageDigest/getInstance "SHA-256")
                                       (doto (.update (.getBytes canonicalized-body "UTF-8")))
                                       (.digest))
                   body-digest-b64 (.encodeToString (Base64/getEncoder) body-digest-bytes)
                   
                   ;; Add DigestValue for Body
                   body-digest-value (.createElementNS doc ds-ns "ds:DigestValue")
                   _ (.appendChild body-digest-value (.createTextNode doc body-digest-b64))
                   _ (.appendChild body-ref body-digest-value)
                   
                   ;; Simple canonicalization for signed-info
                   sw-signed-info (java.io.StringWriter.)
                   _ (-> (javax.xml.transform.TransformerFactory/newInstance)
                        (.newTransformer)
                        (doto (.setOutputProperty OutputKeys/OMIT_XML_DECLARATION "yes"))
                        (doto (.setOutputProperty OutputKeys/ENCODING "UTF-8"))
                        (doto (.setOutputProperty OutputKeys/INDENT "no"))
                        (.transform (javax.xml.transform.dom.DOMSource. signed-info)
                                   (javax.xml.transform.stream.StreamResult. sw-signed-info)))
                   canonicalized-signed-info (.toString sw-signed-info)
                   
                   ;; Add SignatureValue placeholder
                   sig-value (.createElementNS doc ds-ns "ds:SignatureValue")
                   _ (.appendChild sig-element sig-value)
                   
                   ;; Add KeyInfo
                   key-info (.createElementNS doc ds-ns "ds:KeyInfo")
                   _ (.appendChild sig-element key-info)
                   
                   ;; Don't add ID to KeyInfo as it might cause validation issues
                   ;; key-info-id (str "KI-" (java.util.UUID/randomUUID))
                   ;; _ (.setAttributeNS key-info "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" "wsu:Id" key-info-id)
                   
                   ;; Add SecurityTokenReference
                   security-token-ref (.createElementNS doc "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" "wsse:SecurityTokenReference")
                   _ (.appendChild key-info security-token-ref)
                   
                   ;; Don't add ID to SecurityTokenReference as it might cause validation issues
                   ;; str-id (str "STR-" (java.util.UUID/randomUUID))
                   ;; _ (.setAttributeNS security-token-ref "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" "wsu:Id" str-id)
                   
                   ;; Add Reference to certificate
                   cert-ref (.createElementNS doc "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" "wsse:Reference")
                   _ (.setAttribute cert-ref "URI" (str "#" cert-id))
                   _ (.setAttribute cert-ref "ValueType" "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
                   _ (.appendChild security-token-ref cert-ref)]
               
               ;; Sign the values with private key if available
               (when private-key
                 (try
                   (println "Applying XML signature with private key")
                   
                   ;; MUST use SHA1withRSA to match the SignatureMethod algorithm from the spec
                   (let [signature (java.security.Signature/getInstance "SHA1withRSA")
                         sig-info-bytes (.getBytes canonicalized-signed-info "UTF-8")]
                     
                     ;; Initialize signature with private key
                     (.initSign signature private-key)
                     
                     ;; Update with the canonicalized signed-info
                     (.update signature sig-info-bytes)
                     
                     ;; Compute the signature
                     (let [sig-bytes (.sign signature)
                           sig-b64 (.encodeToString (Base64/getEncoder) sig-bytes)]
                       
                       ;; Update the signature value in the document
                       (.appendChild sig-value (.createTextNode doc sig-b64))))
                   
                   (catch Exception e
                     (println "Error signing XML:" (.getMessage e))
                     (.printStackTrace e)))))
           
           
           ;; Now convert to string before returning
           transformer (.newTransformer (javax.xml.transform.TransformerFactory/newInstance))
           _ (.setOutputProperty transformer OutputKeys/ENCODING "UTF-8")
           _ (.setOutputProperty transformer OutputKeys/INDENT "no")
           writer (java.io.StringWriter.)
           _ (.transform transformer (javax.xml.transform.dom.DOMSource. doc) 
                        (javax.xml.transform.stream.StreamResult. writer))
           xml-content (.toString writer)]
       
       ;; Return the XML envelope
       xml-content)
     
     (catch Exception e
       (println "Error creating SOAP envelope:" (.getMessage e))
       (.printStackTrace e)
       ;; Fallback to a simple envelope without signature
       (let [timestamp (format-iso-date)
             op-name (str (Character/toUpperCase (first operation)) (subs operation 1))
             cert-base64 (:base64 cert-info)]
         (str "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">
  <soapenv:Header>
    <wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"
                  xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"
                  soapenv:mustUnderstand=\"1\">
      <wsse:BinarySecurityToken 
          EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\"
          ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"
          wsu:Id=\"X509-certificate\">
        " cert-base64 "
      </wsse:BinarySecurityToken>
      <wsu:Timestamp wsu:Id=\"TS-1\">
        <wsu:Created>" (:created timestamp) "</wsu:Created>
        <wsu:Expires>" (:expires timestamp) "</wsu:Expires>
      </wsu:Timestamp>
    </wsse:Security>
  </soapenv:Header>
  <soapenv:Body xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"
              wsu:Id=\"id-body\">
    <" prefix ":" op-name " xmlns:" prefix "=\"" namespace "\">
      <" prefix ":nifTitular>" (:nif cert-info) "</" prefix ":nifTitular>
      <" prefix ":tipoEnvio>2</" prefix ":tipoEnvio>
    </" prefix ":" op-name ">
  </soapenv:Body>
</soapenv:Envelope>"))))))

;; Create a trust manager that does not validate certificate chains
(defn create-trust-all-manager []
  (into-array 
   javax.net.ssl.TrustManager
   [(proxy [javax.net.ssl.X509TrustManager] []
      (getAcceptedIssuers [] (make-array java.security.cert.X509Certificate 0))
      (checkClientTrusted [_ _] nil)
      (checkServerTrusted [_ _] nil))]))

;; Create SSL context that trusts all certificates
(defn create-ssl-context []
  (let [context (javax.net.ssl.SSLContext/getInstance "TLS")
        trust-managers (create-trust-all-manager)]
    (.init context nil trust-managers (java.security.SecureRandom.))
    context))

;; Send SOAP request to DEHú
(defn send-soap-request [endpoint envelope]
  (try
    (println "Sending SOAP request to:" endpoint)
    (println "Envelope size:" (count envelope))
    
    ;; Create a permissive SSL context
    (let [ssl-context (create-ssl-context)
          ;; Use our ssl context to create the client
          client (-> (HttpClients/custom)
                    (.setSSLContext ssl-context)
                    (.setSSLHostnameVerifier org.apache.http.conn.ssl.NoopHostnameVerifier/INSTANCE)
                    (.build))
          post (HttpPost. endpoint)
          entity (StringEntity. envelope "UTF-8")]
      
      ;; Set up headers
      (.setEntity post entity)
      (.addHeader post "Content-Type" "text/xml; charset=utf-8")
      (.addHeader post "SOAPAction" "")
      (.addHeader post "Expect" "100-continue")
      
      ;; Execute request
      (let [response (.execute client post)
            status (.getStatusLine response)
            status-code (.getStatusCode status)
            ;; Use Latin-1 (ISO-8859-1) encoding to properly handle Spanish characters
            body (EntityUtils/toString (.getEntity response) "ISO-8859-1")]
        
        (println "Received response with status:" status-code)
        
        ;; Return result
        {:status status-code :body body}))
    
    (catch Exception e
      (println "Error sending SOAP request:" (.getMessage e))
      (.printStackTrace e)
      {:status -1 :body (str "Error: " (.getMessage e))})))

;; Detect correct namespace for operation
(defn get-namespace-for-operation [operation]
  (cond
    ;; Notification methods use localiza namespace
    (#{"localiza" "peticionAcceso" "consultaAnexos" "consultaAcusePdf"} operation)
    "http://administracion.gob.es/punto-unico-notificaciones/localiza"
    
    ;; Communications methods use realizadas namespace
    (#{"localizaRealizadas" "consultaRealizadas"} operation)
    "http://administracion.gob.es/punto-unico-notificaciones/realizadas"
    
    ;; Default namespace
    :else
    "http://administracion.gob.es/punto-unico-notificaciones/localiza"))

;; Main function to call DEHú service
(defn call-dehu-service 
  "Makes a direct call to a DEHú SOAP service using simple HTTP"
  ([endpoint operation params user-nif cert-file]
   (call-dehu-service endpoint operation params user-nif cert-file nil))
  
  ([endpoint operation params user-nif cert-file key-file]
   (ssl/disable-ssl-verification)
   (ssl/set-system-properties-for-ssl)
   
   (println "Calling DEHú operation:" operation "with params:" params)
   
   ;; Load certificate and extract information
   (let [cert-info (load-certificate-info cert-file)]
     (if cert-info
       (do
         (println "Certificate loaded successfully")
         
         ;; Use the NIF from the certificate if available, otherwise use the provided NIF
         (let [cert-nif (:nif cert-info)
               effective-nif (or cert-nif user-nif)
               ;; We need the CN for other purposes, but don't use it as the nifTitular
               cn (:cn cert-info)
               
               ;; If params contains nifTitular, update it with the NIF from the certificate
               ;; NOT the CN value (which was incorrect)
               updated-params (if (and (map? params) (:nifTitular params))
                               (assoc params :nifTitular effective-nif)
                               params)
               
               ;; Get proper namespace for operation
               namespace (get-namespace-for-operation operation)
               prefix (if (str/includes? namespace "realizadas") "ns3" "ns2")
               
               ;; Create SOAP envelope with the certificate info
               envelope (create-soap-envelope operation updated-params cert-info key-file namespace prefix)
               
               ;; Send request to DEHú environment
               response (send-soap-request endpoint envelope)]
           
           ;; Return results
           response))
       
       ;; Error loading certificate
       {:status -1 :body "Failed to load certificate"}))))
