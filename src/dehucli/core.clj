(ns dehucli.core
  (:import [javax.xml.namespace QName]
           [org.apache.cxf.endpoint.dynamic DynamicClientFactory]
           [org.apache.cxf.service.model MessagePartInfo])
  (:gen-class))

(defn make-soap-call 
  "Makes a simple SOAP call to a web service.
   - wsdl-url: The URL of the WSDL
   - operation: The name of the operation to call
   - params: The parameters to pass to the operation"
  [wsdl-url operation & params]
  (let [dcf (DynamicClientFactory/newInstance)
        client (.createClient dcf wsdl-url)]
    (try
      (let [result (if (seq params)
                     (.invoke client operation (into-array Object params))
                     (.invoke client operation))]
        {:success true :result result})
      (catch Exception e
        (println (.printStackTrace e))
        {:success false :error (.getMessage e)}))))

(defn -main [& args]
  (println "Hello, DEHú CLI!")
  (println "This is a client for the Spanish DEHú service (LEMA)")
  
  ;; Example SOAP call to a public test web service
  ;; Note: This is just a sample - you'll need to replace with DEHú service details
  (let [test-wsdl "https://www.dataaccess.com/webservicesserver/NumberConversion.wso?WSDL"
        operation "NumberToWords"
        result (make-soap-call test-wsdl operation (java.math.BigInteger. "42"))]
    
    (println "\nTesting SOAP call:")
    (if (:success result)
      (do
        (println "SOAP call successful!")
        (println "Result:" (first (:result result))))
      (println "SOAP call failed:" (:error result)))))