(ns dehucli.core
  (:require [clojure.string :as str]
            [clojure.tools.cli :refer [parse-opts]]
            [dehucli.ssl :as ssl])
  (:import [java.util Properties]
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
   ["-o" "--output-dir DIR" "Directory to save binary data (notifications, annexes, receipts)"]
   ["-p" "--password PWD" "Password for the private key" 
    :default "password"]
   ["-h" "--help" "Show this help"]])

;; Define environment URLs based on the specification
(def wsdl-urls
  {:se {:main "https://se-gd-dehuws.redsara.es/ws/v2/lema?wsdl"
        :realizadas "https://se-gd-dehuws.redsara.es/ws/v1/realizadas?wsdl"}
   :pro {:main "https://gd-dehuws.redsara.es/ws/v2/lema?wsdl"
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
        "  check-certificate        Validate a certificate for DEHú"
        ""
        "Examples:"
        "  dehucli -u 12345678A -c cert.pem -k key.pem localiza"
        "  dehucli -u 12345678A -c cert.pem -k key.pem peticion-acceso 9876543210abcdef"
        "  dehucli -c cert.pem check-certificate"
        ""]
       (str/join \newline)))

(defn error-msg [errors]
  (str "The following errors occurred while parsing your command:\n\n"
       (str/join \newline errors)))

(defn exit [status msg]
  (println msg)
  (System/exit status))

;; This function has been removed as part of cleanup
;; The CLI now exclusively uses dehucli.direct-client for SOAP message generation

;; This function has been removed as it used the CXF client approach
;; Replaced with the direct_client implementation below

;; Parse SOAP fault message
(defn extract-soap-fault [soap-xml]
  (try
    (if-let [fault-string (second (re-find #"<faultstring>(.*?)</faultstring>" soap-xml))]
      ;; Convert the fault string to UTF-8 for proper display (assuming it's in Latin-1/ISO-8859-1)
      (String. (.getBytes fault-string "ISO-8859-1") "UTF-8")
      "Unknown SOAP fault")
    (catch Exception e
      (println "Error extracting SOAP fault:" (.getMessage e))
      "Could not parse SOAP fault")))

;; Use the direct HTTP client which is more reliable
(defn make-soap-call 
  "Makes a SOAP call to DEHú service using direct HTTP client"
  [endpoint operation params certificate private-key]
  (require 'dehucli.direct-client)
  (let [direct-client (resolve 'dehucli.direct-client/call-dehu-service)
        ;; Extract the username from the params for direct client
        username (if (map? params) (:nifTitular params) (:username params))
        ;; Remove the ?wsdl suffix if present
        clean-endpoint (str/replace endpoint #"\?wsdl$" "")
        ;; Call the service with the certificate and private key for signature
        response (direct-client clean-endpoint operation params username certificate private-key)]
    
    ;; Special handling for SOAP faults - we want to extract the fault message
    (if (and (= (:status response) 400)
             (str/includes? (:body response) "<SOAP-ENV:Fault>"))
      {:success false :error (extract-soap-fault (:body response))}
      
      ;; Standard response handling
      (if (= (:status response) 200)
        {:success true :result (:body response)}
        {:success false :error (:body response)}))))

;; Pretty print function for DEHú responses
(defn pretty-print-notifications [notifications]
  (println "Found" (count notifications) "notifications:\n")
  (doseq [notif notifications]
    (println (str "ID: " (:id notif)))
    (println (str "Organization: " (:org notif)))
    (println (str "Date: " (:date notif)))
    (println (str "State: " (:state notif)))
    (println (str "Type: " (:type notif)))
    (println "------------------")))

(defn pretty-print-notification [notification]
  (println (str "ID: " (:id notification)))
  (println (str "Organization: " (:org notification)))
  (println (str "Date: " (:date notification)))
  (println (str "Content: " (if (:content notification) "[CONTENT AVAILABLE]" "[NO CONTENT]")))
  
  (when-let [annexes (:annexes notification)]
    (println "\nAnnexes:")
    (doseq [annex annexes]
      (println (str "  - " (:name annex) " (" (:mime-type annex) ")")
               "\n    Reference: " (:reference annex)))))

;; Parse SOAP response body for localiza
(defn parse-localiza-response [xml-body]
  (try
    ;; Use regex to extract the notification data since we don't need full XML parsing
    (let [notification-pattern #"<ns3:notificacion.*?</ns3:notificacion>"
          notifications (re-seq notification-pattern xml-body)]
      
      ;; Extract data from each notification
      (map (fn [notification-xml]
             (let [id (second (re-find #"<ns3:identificador>(.*?)</ns3:identificador>" notification-xml))
                   org (second (re-find #"<ns3:organismo>(.*?)</ns3:organismo>" notification-xml))
                   date (second (re-find #"<ns3:fecha>(.*?)</ns3:fecha>" notification-xml))
                   type (second (re-find #"<ns3:tipo>(.*?)</ns3:tipo>" notification-xml))
                   concept (second (re-find #"<ns3:concepto>(.*?)</ns3:concepto>" notification-xml))]
               {:id id
                :org org
                :date date
                :type type
                :concept concept}))
           notifications))
    (catch Exception e
      (println "Error parsing response:" (.getMessage e))
      (.printStackTrace e)
      [])))

;; Handle DEHú error codes with specific messages
(defn handle-dehu-error [error-message]
  (cond
    ;; Not registered in the system
    (re-find #"4102.*No está dado de alta" error-message)
    (str "Error: The NIF is not registered as a 'Gran Destinatario' in DEHú\n"
         "You must register this NIF with DEHú before you can use the service.\n"
         "Original message: " error-message)
    
    ;; Authentication error
    (re-find #"(4101|4104).*" error-message)
    (str "Error: Authentication failed with DEHú\n"
         "Please check that your certificate and key are valid and properly loaded.\n"
         "Original message: " error-message)
    
    ;; Default case - return original message
    :else
    (str "Error: " error-message)))

;; Command implementations
(defn cmd-localiza [options args]
  (let [env (keyword (:environment options))
        endpoint (get-in wsdl-urls [env :main])
        params {:nifTitular (:username options)
                :tipoEnvio "2"}] ;; 2 for notifications
    (println "Listing pending notifications...")
    (let [result (make-soap-call endpoint "localiza" params 
                                (:certificate options) 
                                (:key options))]
      (if (:success result)
        (do
          (println "Success!")
          (if-let [result-body (:result result)]
            (let [notifications (parse-localiza-response result-body)]
              (if (and (seq notifications) (not (empty? notifications)))
                (pretty-print-notifications notifications)
                (println "No notifications found")))
            (println "No response body received")))
        (println (handle-dehu-error (:error result)))))))

(defn cmd-peticion-acceso [options args]
  (if-let [id (first args)]
    (let [env (keyword (:environment options))
          endpoint (get-in wsdl-urls [env :main])
          params {:identificador id
                  :codigoOrigen "2"
                  :nifReceptor (:username options)
                  :nombreReceptor (:username options)
                  :evento "1"
                  :concepto "Notification"}]
      (println "Accessing notification:" id)
      (let [result (make-soap-call endpoint "peticionAcceso" params 
                                  (:certificate options) 
                                  (:key options))]
        (if (:success result)
          (do
            (println "Success!")
            (if-let [notification (:notification result)]
              (pretty-print-notification notification)
              (println "Unexpected response format:" result)))
          (println "Failed:" (:error result)))))
    (println "Error: Missing notification ID")))

(defn cmd-consulta-anexos [options args]
  (if (>= (count args) 2)
    (let [id (first args)
          ref (second args)
          env (keyword (:environment options))
          endpoint (get-in wsdl-urls [env :main])
          params {:identificador id
                  :codigoOrigen "2"
                  :nifReceptor (:username options)
                  :referencia ref}]
      (println "Getting annex for notification:" id "with reference:" ref)
      (let [result (make-soap-call endpoint "consultaAnexos" params 
                                  (:certificate options) 
                                  (:key options))]
        (if (:success result)
          (do
            (println "Success!")
            ;; Handle the binary content - this could be saved to file
            (if-let [raw-response (:raw-response result)]
              (do
                (println "Received annex content, size:" (count raw-response) "bytes")
                ;; TODO: Save to file based on mime type
                (println "Add code to save the content to a file"))
              (println "Unexpected response format:" result)))
          (println "Failed:" (:error result)))))
    (println "Error: Missing notification ID or reference")))

(defn cmd-consulta-acuse [options args]
  (if (>= (count args) 2)
    (let [id (first args)
          csv (second args)
          env (keyword (:environment options))
          endpoint (get-in wsdl-urls [env :main])
          params {:identificador id
                  :codigoOrigen "2"
                  :nifReceptor (:username options)
                  :identificadorAcusePdf {:csvResguardo csv}}]
      (println "Getting receipt for notification:" id "with CSV:" csv)
      (let [result (make-soap-call endpoint "consultaAcusePdf" params 
                                  (:certificate options) 
                                  (:key options))]
        (if (:success result)
          (do
            (println "Success!")
            ;; Handle the PDF content - this should be saved to file
            (if-let [raw-response (:raw-response result)]
              (do
                (println "Received PDF receipt, size:" (count raw-response) "bytes")
                ;; TODO: Save to file
                (println "Add code to save the PDF to a file"))
              (println "Unexpected response format:" result)))
          (println "Failed:" (:error result)))))
    (println "Error: Missing notification ID or CSV")))

(defn cmd-localiza-realizadas [options args]
  (let [env (keyword (:environment options))
        endpoint (get-in wsdl-urls [env :realizadas])
        params {:nifTitular (:username options)
                :tipoEnvio "2"}] ;; 2 for notifications
    (println "Listing processed notifications...")
    (let [result (make-soap-call endpoint "localizaRealizadas" params 
                                (:certificate options) 
                                (:key options))]
      (if (:success result)
        (do
          (println "Success!")
          ;; Handle similar to localiza
          (if-let [notifications (:notifications result)]
            (pretty-print-notifications notifications)
            (println "No processed notifications found or unexpected response format:" result)))
        (println "Failed:" (:error result))))))

(defn cmd-consulta-realizadas [options args]
  (if-let [id (first args)]
    (let [env (keyword (:environment options))
          endpoint (get-in wsdl-urls [env :realizadas])
          params {:identificador id
                  :codigoOrigen "2"
                  :nifPeticion (:username options)
                  :nombrePeticion (:username options)
                  :concepto "Notification"}]
      (println "Getting processed notification:" id)
      (let [result (make-soap-call endpoint "consultaRealizadas" params 
                                  (:certificate options) 
                                  (:key options))]
        (if (:success result)
          (do
            (println "Success!")
            ;; Handle similar to peticionAcceso
            (if-let [notification (:notification result)]
              (pretty-print-notification notification)
              (println "Unexpected response format:" result)))
          (println "Failed:" (:error result)))))
    (println "Error: Missing notification ID")))

(defn cmd-check-certificate [options args]
  (if-let [cert-file (:certificate options)]
    (do
      (println "Checking certificate:" cert-file)
      (require 'dehucli.certificate-utils)
      ((resolve 'dehucli.certificate-utils/display-certificate-info) cert-file))
    (println "Error: Certificate path (-c, --certificate) is required")))

(defn -main [& args]
  ;; For testing purposes, disable SSL verification 
  ;; IMPORTANT: This is insecure and should only be used for testing
  (println "Setting up SSL for DEHú connection...")
  (ssl/disable-ssl-verification)
  (ssl/set-system-properties-for-ssl)
  
  (let [{:keys [options arguments errors summary]} (parse-opts args cli-options)]
    ;; Handle help and error conditions
    (cond
      (:help options)
      (exit 0 (usage summary))
      
      errors
      (exit 1 (error-msg errors))
      
      (empty? arguments)
      (exit 1 (usage summary))
      
      ;; Only require username if not doing a certificate check
      (and 
       (not= (first arguments) "check-certificate")
       (nil? (:username options)))
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
          "check-certificate" (cmd-check-certificate options cmd-args)
          
          ;; Default - unknown command
          (exit 1 (str "Unknown command: " command "\n\n" (usage summary))))))))