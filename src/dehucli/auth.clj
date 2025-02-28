(ns dehucli.auth
  (:require [clojure.java.io :as io])
  (:import [java.io File]))

(defn create-auth-context
  "Creates an authentication context for the DEHú API.
   Options:
   - :username   - Username/NIF for authentication
   - :cert       - Path to certificate file
   - :key        - Path to private key file
   - :password   - Password for the private key (if needed)
   - :debug      - Enable debug mode"
  [options]
  (let [username (:username options)
        cert-file (when (:cert options) (io/file (:cert options)))
        key-file (when (:key options) (io/file (:key options)))
        password (:password options)
        debug (:debug options)]
    
    ;; Validate inputs
    (when (and cert-file (not (.exists cert-file)))
      (throw (ex-info "Certificate file not found" {:file cert-file})))
    
    (when (and key-file (not (.exists key-file)))
      (throw (ex-info "Key file not found" {:file key-file})))
    
    ;; Create the auth context
    {:username username
     :cert-file cert-file
     :key-file key-file
     :password password
     :debug debug}))