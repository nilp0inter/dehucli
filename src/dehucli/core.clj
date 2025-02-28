(ns dehucli.core
  (:require [clojure.string :as str]
            [clojure.tools.cli :refer [parse-opts]])
  (:import [javax.xml.namespace QName]
           [org.apache.cxf.endpoint.dynamic DynamicClientFactory]
           [org.apache.cxf.endpoint Client]
           [org.apache.cxf.binding.soap SoapBindingConstants]
           [org.apache.cxf.ws.security.wss4j WSS4JOutInterceptor]
           [org.apache.wss4j.dom WSConstants]
           [org.apache.wss4j.common.ext WSSecurityException]
           [java.util Properties HashMap]
           [javax.xml.ws BindingProvider]
           [java.security KeyStore]
           [java.security.cert X509Certificate])
  (:gen-class))

;; Define the DEHú CLI options
(def cli-options
  [["-u" "--username NIF" "NIF for authentication"]
   ["-c" "--certificate PATH" "Path to X.509 certificate file"]
   ["-k" "--key PATH" "Path to private key file"]
   ["-e" "--environment ENV" "Environment: 'se' for testing, 'pro' for production"
    :default "se"
    :validate [#(contains? #{"se" "pro"} %) "Must be 'se' or 'pro'"]]
   ["-h" "--help" "Show this help"]])

;; Define environment URLs based on the specification
(def wsdl-urls
  {:se {:main "https://se-gd-dehuws.redsara.es/ws/v2/lema"
        :realizadas "https://se-gd-dehuws.redsara.es/ws/v1/realizadas?wsdl"}
   :pro {:main "https://gd-dehuws.redsara.es/ws/v2/lema"
         :realizadas "https://gd-dehuws.redsara.es/ws/v1/realizadas?wsdl"}})

(defn usage [options-summary]
  (->> ["DEHú CLI - Client for the Spanish DEHú (LEMA) service"
        ""
        "Usage: dehucli [options] command [args]"
        ""
        "Options:"
        options-summary
        ""
        "Commands:"
        "  localiza                 List pending notifications"
        "  peticion-acceso ID       Access a notification content"
        "  consulta-anexos ID REF   Get an annex by reference"
        "  consulta-acuse ID CSV    Get receipt PDF"
        "  localiza-realizadas      List processed notifications"
        "  consulta-realizadas ID   Get processed notification content"
        ""
        "Examples:"
        "  dehucli -u 12345678A -c cert.pem -k key.pem localiza"
        "  dehucli -u 12345678A -c cert.pem -k key.pem peticion-acceso 9876543210abcdef"
        ""]
       (str/join \newline)))

(defn error-msg [errors]
  (str "The following errors occurred while parsing your command:\n\n"
       (str/join \newline errors)))

(defn exit [status msg]
  (println msg)
  (System/exit status))

(defn setup-ws-security
  "Sets up WS-Security for the SOAP client using X.509 certificate"
  [client certificate private-key]
  (let [outProps (Properties.)
        interceptor (WSS4JOutInterceptor.)]
    ;; Configure WS-Security properties
    (doto outProps
      (.put "action" "Signature")
      (.put "signaturePropFile" "crypto.properties")
      (.put "signatureKeyIdentifier" "DirectReference")
      (.put "signatureAlgorithm" WSConstants/RSA_SHA1)
      (.put "digestAlgorithm" "http://www.w3.org/2000/09/xmldsig#sha256")
      (.put "user" certificate)
      (.put "passwordCallbackClass" "dehucli.PasswordCallback"))
    
    ;; Add the interceptor to the client
    (.setProperties interceptor outProps)
    (-> client
        (.getOutInterceptors)
        (.add interceptor))))

(defn make-soap-call 
  "Makes a SOAP call to DEHú service"
  [wsdl-url operation params certificate private-key]
  (println (str "Calling operation: " operation " at " wsdl-url))
  (let [dcf (DynamicClientFactory/newInstance)
        client (.createClient dcf wsdl-url)]
    
    ;; Setup WS-Security if certificate and key are provided
    (when (and certificate private-key)
      (setup-ws-security client certificate private-key))
    
    ;; Set up timeout
    (doto client
      (.getRequestContext)
      (.put "javax.xml.ws.client.connectionTimeout" (Integer. 30000))
      (.put "javax.xml.ws.client.receiveTimeout" (Integer. 60000)))
    
    (try
      (let [result (if (empty? params)
                     (.invoke client operation (into-array Object []))
                     (.invoke client operation 
                              (into-array Object 
                                          [params])))]
        {:success true :result result})
      (catch Exception e
        (println (.getMessage e))
        {:success false :error (.getMessage e)}))))

;; Command implementations
(defn cmd-localiza [options args]
  (let [env (keyword (:environment options))
        wsdl-url (get-in wsdl-urls [env :main])
        params {:nifTitular (:username options)
                :tipoEnvio "2"}] ;; 2 for notifications
    (println "Listing pending notifications...")
    (let [result (make-soap-call wsdl-url "localiza" params 
                                (:certificate options) 
                                (:key options))]
      (if (:success result)
        (do
          (println "Success!")
          (println "Result:" (first (:result result))))
        (println "Failed:" (:error result))))))

(defn cmd-peticion-acceso [options args]
  (if-let [id (first args)]
    (let [env (keyword (:environment options))
          wsdl-url (get-in wsdl-urls [env :main])
          params {:identificador id
                  :codigoOrigen "2"
                  :nifReceptor (:username options)
                  :nombreReceptor (:username options)
                  :evento "1"
                  :concepto "Notification"}]
      (println "Accessing notification:" id)
      (let [result (make-soap-call wsdl-url "peticionAcceso" params 
                                  (:certificate options) 
                                  (:key options))]
        (if (:success result)
          (do
            (println "Success!")
            (println "Result:" (first (:result result))))
          (println "Failed:" (:error result)))))
    (println "Error: Missing notification ID")))

(defn cmd-consulta-anexos [options args]
  (if (>= (count args) 2)
    (let [id (first args)
          ref (second args)
          env (keyword (:environment options))
          wsdl-url (get-in wsdl-urls [env :main])
          params {:identificador id
                  :codigoOrigen "2"
                  :nifReceptor (:username options)
                  :referencia ref}]
      (println "Getting annex for notification:" id "with reference:" ref)
      (let [result (make-soap-call wsdl-url "consultaAnexos" params 
                                  (:certificate options) 
                                  (:key options))]
        (if (:success result)
          (do
            (println "Success!")
            (println "Result:" (first (:result result))))
          (println "Failed:" (:error result)))))
    (println "Error: Missing notification ID or reference")))

(defn cmd-consulta-acuse [options args]
  (if (>= (count args) 2)
    (let [id (first args)
          csv (second args)
          env (keyword (:environment options))
          wsdl-url (get-in wsdl-urls [env :main])
          params {:identificador id
                  :codigoOrigen "2"
                  :nifReceptor (:username options)
                  :identificadorAcusePdf {:csvResguardo csv}}]
      (println "Getting receipt for notification:" id "with CSV:" csv)
      (let [result (make-soap-call wsdl-url "consultaAcusePdf" params 
                                  (:certificate options) 
                                  (:key options))]
        (if (:success result)
          (do
            (println "Success!")
            (println "Result:" (first (:result result))))
          (println "Failed:" (:error result)))))
    (println "Error: Missing notification ID or CSV")))

(defn cmd-localiza-realizadas [options args]
  (let [env (keyword (:environment options))
        wsdl-url (get-in wsdl-urls [env :realizadas])
        params {:nifTitular (:username options)
                :tipoEnvio "2"}] ;; 2 for notifications
    (println "Listing processed notifications...")
    (let [result (make-soap-call wsdl-url "localizaRealizadas" params 
                                (:certificate options) 
                                (:key options))]
      (if (:success result)
        (do
          (println "Success!")
          (println "Result:" (first (:result result))))
        (println "Failed:" (:error result))))))

(defn cmd-consulta-realizadas [options args]
  (if-let [id (first args)]
    (let [env (keyword (:environment options))
          wsdl-url (get-in wsdl-urls [env :realizadas])
          params {:identificador id
                  :codigoOrigen "2"
                  :nifPeticion (:username options)
                  :nombrePeticion (:username options)
                  :concepto "Notification"}]
      (println "Getting processed notification:" id)
      (let [result (make-soap-call wsdl-url "consultaRealizadas" params 
                                  (:certificate options) 
                                  (:key options))]
        (if (:success result)
          (do
            (println "Success!")
            (println "Result:" (first (:result result))))
          (println "Failed:" (:error result)))))
    (println "Error: Missing notification ID")))

(defn -main [& args]
  (let [{:keys [options arguments errors summary]} (parse-opts args cli-options)]
    ;; Handle help and error conditions
    (cond
      (:help options)
      (exit 0 (usage summary))
      
      errors
      (exit 1 (error-msg errors))
      
      (empty? arguments)
      (exit 1 (usage summary))
      
      (nil? (:username options))
      (exit 1 "Error: Username/NIF is required (-u or --username)")
      
      ;; In a real implementation, check certificate and key
      ;; (or (nil? (:certificate options)) (nil? (:key options)))
      ;; (exit 1 "Error: Both certificate and key are required")
      
      :else
      (let [command (first arguments)
            cmd-args (rest arguments)]
        (case command
          "localiza" (cmd-localiza options cmd-args)
          "peticion-acceso" (cmd-peticion-acceso options cmd-args)
          "consulta-anexos" (cmd-consulta-anexos options cmd-args)
          "consulta-acuse" (cmd-consulta-acuse options cmd-args)
          "localiza-realizadas" (cmd-localiza-realizadas options cmd-args)
          "consulta-realizadas" (cmd-consulta-realizadas options cmd-args)
          
          ;; Default - unknown command
          (exit 1 (str "Unknown command: " command "\n\n" (usage summary))))))))