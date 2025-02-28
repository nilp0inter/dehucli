(ns dehucli.ssl
  (:import [javax.net.ssl X509TrustManager SSLContext TrustManager]
           [java.security SecureRandom]
           [java.security.cert X509Certificate]))

;; Create a trust manager that does not validate certificate chains
(def trust-all-certs
  (into-array TrustManager
              [(proxy [X509TrustManager] []
                 (getAcceptedIssuers [] (make-array X509Certificate 0))
                 (checkClientTrusted [^"[Ljava.security.cert.X509Certificate;" certs ^String authType])
                 (checkServerTrusted [^"[Ljava.security.cert.X509Certificate;" certs ^String authType]))]))

(defn disable-ssl-verification
  "Disable SSL certificate verification. USE WITH CAUTION - for testing only!"
  []
  (println "WARNING: Disabling SSL certificate verification. This is insecure!")
  (let [sc (SSLContext/getInstance "TLS")]
    (.init sc nil trust-all-certs (SecureRandom.))
    (javax.net.ssl.HttpsURLConnection/setDefaultSSLSocketFactory (.getSocketFactory sc))
    (javax.net.ssl.HttpsURLConnection/setDefaultHostnameVerifier
     (proxy [javax.net.ssl.HostnameVerifier] []
       (verify [hostname session] true)))))

(defn set-system-properties-for-ssl
  "Set system properties to help with SSL connections"
  []
  (System/setProperty "javax.net.ssl.trustStore" "jssecacerts")
  (System/setProperty "javax.net.ssl.trustStorePassword" "changeit")
  (System/setProperty "com.sun.xml.ws.transport.http.client.HttpTransportPipe.dump" "true")
  (System/setProperty "com.sun.xml.internal.ws.transport.http.client.HttpTransportPipe.dump" "true")
  (System/setProperty "com.sun.xml.ws.transport.http.HttpAdapter.dump" "true")
  (System/setProperty "com.sun.xml.internal.ws.transport.http.HttpAdapter.dump" "true")
  (System/setProperty "com.sun.xml.ws.transport.http.HttpAdapter.dumpTreshold" "9999999")
  (System/setProperty "com.sun.xml.internal.ws.transport.http.HttpAdapter.dumpTreshold" "9999999"))