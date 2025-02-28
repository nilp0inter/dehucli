(ns dehucli.test
  (:require [dehucli.api :as api]
            [dehucli.auth :as auth])
  (:import [java.math BigInteger]))

(defn test-wsdl-connection []
  (println "Testing WSDL connection...")
  
  ;; Test a public SOAP service first 
  (let [wsdl-url "https://www.dataaccess.com/webservicesserver/NumberConversion.wso?WSDL"
        auth-context {:debug true}]
    (println "Testing public NumberConversion service...")
    (try
      ;; For the NumberToWords operation, the parameter should be a BigInteger directly
      (let [result (api/make-soap-call wsdl-url "NumberToWords" 
                                      (BigInteger. "42")
                                      auth-context)]
        (println "Result:" result))
      (catch Exception e
        (println "Error:" (.getMessage e))
        (.printStackTrace e)))))

(defn test-dehu-connection []
  (println "\nTesting DEHú connection...")
  (let [wsdl-url "https://se-gd-dehuws.redsara.es/ws/v2/lema?wsdl"
        auth-context {:debug true
                      :username "12345678Z"}] ; Sample username
    (println "Testing DEHú LEMA service...")
    (try
      ;; Try to get the WSDL definition
      (let [result (api/make-soap-call wsdl-url "localiza" 
                                      {:nifTitular "12345678Z"
                                       :tipoEnvio "2"}
                                      auth-context)]
        (println "Result:" result))
      (catch Exception e
        (println "Error connecting to DEHú:" (.getMessage e))))))

(defn -main [& args]
  (test-wsdl-connection)
  ;; Uncomment to test DEHú connection - currently will fail without proper auth
  ;; (test-dehu-connection)
  (System/exit 0))

;; Run the test when loaded directly
(when (= *file* (System/getProperty "babashka.file"))
  (-main))