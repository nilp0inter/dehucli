(ns dehucli.PasswordCallback
  (:gen-class
   :implements [javax.security.auth.callback.CallbackHandler])
  (:import [org.apache.wss4j.common.ext WSPasswordCallback]))

(defn -handle
  "Handle the password callback"
  [this callbacks]
  (doseq [callback callbacks]
    (when (instance? WSPasswordCallback callback)
      (let [cb ^WSPasswordCallback callback]
        ;; For simplicity, we're using a fixed password here
        ;; In a real implementation, this would be configurable
        (.setPassword cb "password")))))