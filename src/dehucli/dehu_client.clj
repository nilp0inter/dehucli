(ns dehucli.dehu-client
  (:require [clojure.string :as str])
  (:import [org.apache.http.client.methods HttpPost]
           [org.apache.http.entity StringEntity]
           [org.apache.http.impl.client HttpClients]
           [org.apache.http.util EntityUtils]
           [org.apache.http.conn.ssl SSLConnectionSocketFactory TrustSelfSignedStrategy]
           [org.apache.http.ssl SSLContextBuilder]
           [javax.net.ssl SSLContext X509TrustManager]
           [java.security SecureRandom]
           [java.security.cert X509Certificate]))

;; Create a trust manager that does not validate certificate chains
(def trust-all-certs
  (proxy [X509TrustManager] []
    (getAcceptedIssuers [] (make-array java.security.cert.X509Certificate 0))
    (checkClientTrusted [_ _] nil)
    (checkServerTrusted [_ _] nil)))

(defn create-soap-client []
  ;; Create a client that trusts all certificates
  (let [ssl-context (SSLContext/getInstance "TLS")]
    ;; Use our trust-all-certs manager
    (.init ssl-context nil (into-array [trust-all-certs]) (SecureRandom.))
    
    ;; Register the SSL context
    (SSLContext/setDefault ssl-context)
    
    ;; Create the client with SSL disabled
    (-> (HttpClients/custom)
        (.setSSLContext ssl-context)
        (.setSSLHostnameVerifier org.apache.http.conn.ssl.NoopHostnameVerifier/INSTANCE)
        (.build))))

(defn build-soap-envelope 
  ([operation params]
   (build-soap-envelope operation params "http://administracion.gob.es/punto-unico-notificaciones/localiza" "loc"))
  
  ([operation params namespace prefix]
   (str "<?xml version=\"1.0\" encoding=\"utf-8\"?>
<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">
  <soapenv:Header>
    <wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"
                  xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">
      <wsu:Timestamp wsu:Id=\"Id-timestamp\">
        <wsu:Created>" (.format (java.text.SimpleDateFormat. "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'") 
                                 (java.util.Date.)) "</wsu:Created>
        <wsu:Expires>" (.format (java.text.SimpleDateFormat. "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'") 
                                (java.util.Date. (+ (System/currentTimeMillis) (* 5 60 1000)))) "</wsu:Expires>
      </wsu:Timestamp>
    </wsse:Security>
  </soapenv:Header>
  <soapenv:Body wsu:Id=\"id-body\"
              xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">
    <ns2:" operation " xmlns:ns2=\"" namespace "\"
                     xmlns:ns3=\"http://administracion.gob.es/punto-unico-notificaciones/respuestaLocaliza\"
                     xmlns:ns4=\"http://administracion.gob.es/punto-unico-notificaciones/respuestaPeticionAcceso\"
                     xmlns:ns5=\"http://administracion.gob.es/punto-unico-notificaciones/peticionAcceso\"
                     xmlns:ns6=\"http://administracion.gob.es/punto-unico-notificaciones/consultaAcusePdf\"
                     xmlns:ns7=\"http://administracion.gob.es/punto-unico-notificaciones/respuestaConsultaAcusePdf\">
      " (if (map? params)
          (str/join "\n      " 
                   (map (fn [[k v]] 
                          (str "<ns2:" (name k) ">" v "</ns2:" (name k) ">"))
                        params))
          params) "
    </ns2:" operation ">
  </soapenv:Body>
</soapenv:Envelope>")))

(defn call-dehu-service 
  ([endpoint operation params]
   (call-dehu-service endpoint operation params nil))
  
  ([endpoint operation params custom-envelope]
   (let [client (create-soap-client)
         soap-envelope (if custom-envelope
                         custom-envelope
                         (build-soap-envelope operation params))
         _ (println "Sending envelope:\n" soap-envelope)
         post (HttpPost. endpoint)
         entity (StringEntity. soap-envelope "UTF-8")]
    
     ;; Set up the request
     (.setEntity post entity)
     (.addHeader post "Content-Type" "text/xml; charset=utf-8")
     (.addHeader post "SOAPAction" "")
     (.addHeader post "Expect" "100-continue")
    
     ;; Execute the request
     (let [response (.execute client post)
           status (.getStatusLine response)
           status-code (.getStatusCode status)
           body (EntityUtils/toString (.getEntity response))]
      
       ;; Return the response
       {:status status-code
        :body body}))))

;; Example use:
#_(call-dehu-service 
  "https://gd-dehuws.redsara.es/ws/v2/lema" 
  "localiza" 
  {:nifTitular "EXAMPLE_NIF"
   :tipoEnvio "2"})