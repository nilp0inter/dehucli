(ns dehucli.api
  (:require [clojure.string :as str]
            [dehucli.security :as security])
  (:import [javax.xml.namespace QName]
           [org.apache.cxf.endpoint.dynamic DynamicClientFactory]
           [org.apache.cxf.ws.security.wss4j WSS4JOutInterceptor]
           [org.apache.wss4j.dom WSConstants]
           [org.apache.cxf.message Message]
           [org.apache.cxf.interceptor LoggingOutInterceptor LoggingInInterceptor]
           [org.apache.cxf.transport.http HTTPConduit]
           [org.apache.cxf.transports.http.configuration HTTPClientPolicy]
           [java.util HashMap]))

;; Constants for the DEHú API
(def dehu-namespaces
  {:localiza "http://administracion.gob.es/punto-unico-notificaciones/localiza"
   :peticion-acceso "http://administracion.gob.es/punto-unico-notificaciones/peticionAcceso"
   :consulta-anexos "http://administracion.gob.es/punto-unico-notificaciones/consultaAnexos"
   :consulta-acuse-pdf "http://administracion.gob.es/punto-unico-notificaciones/consultaAcusePdf"
   :localiza-realizadas "http://administracion.gob.es/punto-unico-notificaciones/localizaRealizadas"
   :consulta-realizadas "http://administracion.gob.es/punto-unico-notificaciones/consultaRealizadas"})

(defn configure-client
  "Configures the SOAP client with proper settings for DEHú"
  [client auth-context]
  ;; Add WS-Security interceptor if certificate is available
  (when (and (:cert-file auth-context) (:key-file auth-context))
    ;; Initialize the security properties
    (security/create-crypto-properties 
      (:cert-file auth-context)
      (:key-file auth-context)
      (or (:password auth-context) ""))
    
    ;; Create and add the WS-Security interceptor
    (let [outProps (HashMap.)
          interceptor (WSS4JOutInterceptor.)]
      (doto outProps
        (.put "action" "Signature")
        (.put "signaturePropFile" "crypto.properties")
        (.put "signatureKeyIdentifier" "DirectReference")
        (.put "signatureAlgorithm" WSConstants/RSA_SHA1)
        (.put "digestAlgorithm" "http://www.w3.org/2000/09/xmldsig#sha256")
        (.put "user" "dehu-key")
        (.put "passwordCallbackClass" "dehucli.security.PasswordCallback"))
      
      (.setProperties interceptor outProps)
      (-> client
          (.getOutInterceptors)
          (.add interceptor))))
  
  ;; Configure HTTP settings
  (let [http-conduit (.getConduit client)
        client-policy (HTTPClientPolicy.)]
    (doto client-policy
      (.setConnectionTimeout 30000)
      (.setReceiveTimeout 60000)
      (.setAllowChunking false))
    (.setClient http-conduit client-policy))
  
  ;; Add logging interceptors in debug mode
  (when (:debug auth-context)
    (-> client
        (.getOutInterceptors)
        (.add (LoggingOutInterceptor.)))
    (-> client
        (.getInInterceptors)
        (.add (LoggingInInterceptor.))))
  
  ;; Return the configured client
  client)

(defn make-soap-call
  "Makes a SOAP call to the DEHú service"
  [wsdl-url operation params auth-context]
  (let [dcf (DynamicClientFactory/newInstance)
        _ (when (:debug auth-context) (println "Creating client for" wsdl-url))
        client (.createClient dcf wsdl-url)
        _ (when (:debug auth-context) (println "Configuring client"))
        _ (configure-client client auth-context)]
    
    (try
      (when (:debug auth-context) 
        (println "Calling operation:" operation)
        (println "With parameters:" params))
      
      (let [result (if (empty? params)
                     (.invoke client operation (into-array Object []))
                     (.invoke client operation (into-array Object [params])))]
        
        (when (:debug auth-context)
          (println "Call successful, processing result"))
        
        (first result))
      
      (catch Exception e
        (when (:debug auth-context)
          (println "SOAP call failed:")
          (.printStackTrace e))
        
        {:codigoRespuesta "500" 
         :descripcionRespuesta (str "Error: " (.getMessage e))}))))

;; API Functions for DEHú operations

(defn localiza
  "List pending notifications and communications"
  [auth-context wsdl-url params]
  (let [request (merge
                  {:nifTitular (:username auth-context)
                   :tipoEnvio "2"} ; Default to notifications
                  params)]
    (make-soap-call wsdl-url "localiza" request auth-context)))

(defn peticion-acceso
  "Access a notification or communication"
  [auth-context wsdl-url params]
  (let [request (merge
                  {:nifReceptor (:username auth-context)
                   :nombreReceptor (:username auth-context)
                   :evento "1" ; Always "Accepted"
                   :codigoOrigen "2"}
                  params)]
    (make-soap-call wsdl-url "peticionAcceso" request auth-context)))

(defn consulta-anexos
  "Get an annex document by reference"
  [auth-context wsdl-url params]
  (let [request (merge
                  {:nifReceptor (:username auth-context)
                   :codigoOrigen "2"}
                  params)]
    (make-soap-call wsdl-url "consultaAnexos" request auth-context)))

(defn consulta-acuse-pdf
  "Get a receipt PDF by CSV"
  [auth-context wsdl-url params]
  (let [request (merge
                  {:nifReceptor (:username auth-context)
                   :codigoOrigen "2"}
                  params)]
    (make-soap-call wsdl-url "consultaAcusePdf" request auth-context)))

(defn localiza-realizadas
  "List already processed notifications and communications"
  [auth-context wsdl-url params]
  (let [request (merge
                  {:nifTitular (:username auth-context)
                   :tipoEnvio "2"} ; Default to notifications
                  params)]
    (make-soap-call wsdl-url "localizaRealizadas" request auth-context)))

(defn consulta-realizadas
  "Get a processed notification or communication"
  [auth-context wsdl-url params]
  (let [request (merge
                  {:nifPeticion (:username auth-context)
                   :nombrePeticion (:username auth-context)
                   :codigoOrigen "2"}
                  params)]
    (make-soap-call wsdl-url "consultaRealizadas" request auth-context)))