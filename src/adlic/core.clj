(ns adlic.core
  (:require [clojure.string :as str]
            [clj-http.client :as http]))


(def ^:private config (atom {:account nil
                             :key nil
                             :dns-suffix nil}))



(def date-format (doto (java.text.SimpleDateFormat. "EEE, dd MMM yyyy HH:mm:ss")
                   (.setTimeZone (java.util.TimeZone/getTimeZone "Z"))))

(defn format-date [date] (str (.format date-format date) " GMT"))
;; (format-date (java.util.Date.))

(defn sign-hmac-sha256 [text base64-key]
  (-> (doto (javax.crypto.Mac/getInstance "HmacSHA256")
        (.init (-> (.decode (java.util.Base64/getDecoder)
                            (.getBytes base64-key "UTF-8"))
                   (javax.crypto.spec.SecretKeySpec. "HmacSHA256"))))
      (.doFinal (.getBytes text))
      (as-> $ (.encode (java.util.Base64/getEncoder) $))
      (String. "UTF-8")))

(defn init-dl [account key dns-suffix]
  (reset! config (hash-map :account account,
                           :key key,
                           :dns-suffix dns-suffix)))

(defn string-to-sign [req]
  (letfn [(chf [headers]
            (->> headers
                 (filter #(.startsWith (key %) "x-ms-"))
                 (map (fn [[k v]]
                        [(str/trim (.toLowerCase k))
                         ;; TODO should not replace
                         ;;      whitespace inside a quoted string
                         (str/trim (str/replace (str v) #"\s+" " "))]))
                 (sort-by first)
                 (map #(str/join ":" %))
                 (str/join "\n")))
          (crf [{:keys [account uri query-params]}]
            (->> query-params
                 (map (fn [[k v]]
                        ;; key and value must be url decoded
                        ;; value shouldn't contain comma ","
                        [(str/trim (.toLowerCase k)) (str v)]))
                 (sort-by first)
                 (map #(str/join ":" %))
                 (into [(str "/" account uri)])
                 (str/join "\n")))]
    (let [m (assoc req
                   :canonicalized-headers (chf (:headers req))
                   :canonicalized-resource (crf (:resource req)))]
      (->> [:verb
            :content-encoding :content-language :content-length
            :content-md5 :content-type
            :date
            :if-modified-since :if-match :if-none-match :if-unmodified-since
            :range
            :canonicalized-headers
            :canonicalized-resource]
           (map m)
           (str/join "\n")))))

(defn- req-obj
  "INPUT:
  *verb* :string, verb must be any string from the list
         [\"GET\" \"PUT\" \"DELETE\" \"HEAD\" \"POST\" \"PATCH\"]
         NOTE: Only capital letters is supported.
  *query-params*:map, ex: {\"resource\" \"account\"}
  *path*:string
  *options*: map"
  ([verb query-params path]
   (req-obj verb query-params path nil))
  ([verb query-params path options]
   (let [headers (:headers options)
         opt (dissoc options :headers)]
     (merge
      {:verb verb
       :content-encoding nil
       :content-language nil
       :content-length nil
       :content-md5 nil
       :content-type nil
       ;; :date nil
       :if-modified-since nil
       :if-match nil
       :if-none-match nil
       :if-unmodified-since nil
       :range nil
       :headers (merge {"x-ms-client-request-id" (str (java.util.UUID/randomUUID))
                        "x-ms-date" (format-date (java.util.Date.))
                        "x-ms-version" "2018-11-09"} headers)
       :resource {:account (get @config :account)
                  :dns-suffix (get @config :dns-suffix)
                  :uri path
                  :query-params query-params}}
      opt))))

(defn- auth
  "This function return the Sharedkey string.
  INPUT:
  *req* : req object
  OUTPUT:string, \"SharedKey <account-name>:<sign-string>\"
  "
  [req]
  (let [key (get @config :key)]
    (format "SharedKey %s:%s"
            (get-in req [:resource :account])
            (-> req string-to-sign (sign-hmac-sha256 key)))))

(defn- uri [req]
  (let [{:keys [account dns-suffix uri]} (:resource req)]
    (format "https://%s.%s%s" account dns-suffix uri)))

(defn- destruct-path [path]
  (let [split-arr (str/split path #"/")]
    (if (empty? (first split-arr))
      (vec (rest split-arr))
      split-arr)))

(defn- fs-create
  "This function create file system if it doesn't exist.
  INPUT:
  *fs-name*: string, file-system name
  NOTE: file-system RegEx: ^[$a-z0-9](?!.*--)[-a-z0-9]{1,61}[a-z0-9]$
  OUTPUT:
  retrun true if it create fs, otherwise false.
  For DEBUG: follow up the logs of level debug."
  [fs-name]
  (let [path (str "/" fs-name)
        req (req-obj "PUT" {"resource" "filesystem"} path)
        url (uri req)]
    (-> (http/put url
                  {:throw-exceptions false
                   :accept           :json
                   :as               :json
                   :headers          (assoc (:headers req)
                                            "Authorization" (auth req))
                   :query-params     (get-in req [:resource :query-params])})
        )))

(defn- path-list
  "This function list filesystem paths and their properties.
  INPUT:
  *fs-name*: string, file-system name
  OUTPUT:
  return map having keys [:status :resason-parse :body]"
  [fs-name]
  (let [path  (str "/" fs-name)
        req      (req-obj "GET" {"resource" "filesystem"
                                 "recursive" "True"} path)
        url      (uri req)]
    (-> (http/get url
                  {:throw-exceptions false
                   :accept           :json
                   :as               :json
                   :headers          (assoc (:headers req)
                                            "Authorization" (auth req))
                   :query-params     (get-in req [:resource :query-params])})
        (select-keys [:status :reason-phrase :body]))))

(defn- path-create-dir
  "This function return true if it create directories successfully other wise false.
  INPUT:
  *fs-name*: String, file-system name.
  *dir-array*: list, list of directories to find path nestedly.
  OUTPUT:
  return list of true or false as per the directory list.
  For DEBUG: follow up the logs of level debug."
  [fs-name dir-arr]
  (let [path (atom (str "/" fs-name))]
    (if (empty? dir-arr)
      (reduce (fn [result dir-name]
                (let [abs-path (swap! path str "/" dir-name)
                      req      (req-obj "PUT" {"resource" "directory"} abs-path
                                        {:if-none-match "*"
                                         :headers       {"If-None-Match" "*"}})
                      url      (uri req)
                      ]
                  (conj result
                        (-> (http/put url
                                      {:throw-exceptions false
                                       :accept           :json
                                       :as               :json
                                       :headers          (assoc (:headers req)
                                                                "Authorization"
                                                                (auth req))
                                       :query-params     (get-in
                                                          req
                                                          [:resource :query-params])})
                            (select-keys [:status :reason-phrase]))))) [] dir-arr))))


(defn- path-delete-file
  "This function return true if it delete file or file already not exist there
  otherwise return false.
  INPUT:
  *fs-name*: String, file-system name.
  *dir-array*: list, list of directories to find path nestedly.
  *file-name*: String, file name.
  OUTPUT:
  return true of false
  FOR DEBUG: follow up the logs of level debug.
  "
  [fs-name dir-arr file-name]
  (let [path (str "/" fs-name "/" (str/join "/" dir-arr) "/" file-name)
        req (req-obj "DELETE" {"recursive" "True"} path)
        url (uri req)]
    (-> (http/delete url
                     {:throw-exceptions false
                      :accept           :json
                      :as               :json
                      :headers          (assoc (:headers req)
                                               "Authorization" (auth req))
                      :query-params     (get-in req [:resource :query-params])})
        (select-keys [:status :reason-phrase ]))
    ))

(defn- path-create-file
  "This function return true if it create file or if file already exist there.
  otherwise return false.
  INPUT:
  *fs-name*: String, file-system name.
  *dir-array*: list, list of directories to find path nestedly.
  *file-name*: String, file name.
  OUTPUT:
  return true of false
  FOR DEBUG: follow up the logs of level debug.
  "
  [fs-name dir-arr file-name]
  (let [path (str "/" fs-name "/" (str/join "/" dir-arr) "/" file-name)
        req (req-obj "PUT" {"resource" "file"} path
                     {:if-none-match "*"
                      :headers {"If-None-Match" "*"}})
        url (uri req)]
    (-> (http/put url
                  {:throw-exceptions false
                   :accept           :json
                   :as               :json
                   :headers          (assoc (:headers req)
                                            "Authorization" (auth req))
                   :query-params     (get-in req [:resource :query-params])})
        (select-keys [:status :reason-phrase ])
        )
    ))

(defn- path-update-append
  "This function return last position if it append data successfuly other wise false.
  CAUTION: if file already exist and conatians some data it will replace that data
           new one.
  INPUT:
  *fs-name*: String, file-system name.
  *dir-array*: list, list of directories to find path nestedly.
  *file-name*: String, file name.
  *data* : String, data to append.
  *position*: Integer (default = 0), the last position to be flushed.
            NOTE: when appending first time no need to provide postion.
                  By default it is 0 (zero)
  OUTPUT:
  return last append position.
  FOR DEBUG: follow up the logs of level dubug.
  "
  ([fs-name dir-arr file-name data]
   (path-update-append fs-name dir-arr file-name data 0))
  ([fs-name dir-arr file-name data position]
   (let [path    (str "/" fs-name "/" (str/join "/" dir-arr) "/" file-name)
         clen    (count data)
         ctype   "text/plain"
         req     (req-obj "PATCH" {"action" "append" "position" position} path
                          {:content-type ctype :content-length clen})
         url     (uri req)]
     (-> (http/request
          {:method           (:verb req)
           :url              url
           :throw-exceptions false
           :body             data
           :content-type     ctype
           :headers          (assoc (:headers req)
                                    "Authorization" (auth req))
           :query-params     (get-in req [:resource :query-params])})
         (select-keys [:status :reason-phrase]))))
  )

(defn- path-update-flush
  "This function return true if it flush data successfuly other wise false
  INPUT:
  *fs-name*: String, file-system name.
  *dir-array*: list, list of directories to find path nestedly.
  *file-name*: String, file name.
  *position*: Integer, the last position to be flushed.
  OUTPUT:
  return true or false
  FOR DEBUG: follow up the logs of debug level.
  "
  [fs-name dir-arr file-name position]
  (let [path    (str "/" fs-name "/" (str/join "/" dir-arr) "/" file-name)
        req     (req-obj "PATCH" {"action" "flush" "position" position} path
                         {:headers {"Content-Length" 0}})
        url     (uri req)]
    (-> (http/request
         {:method           (:verb req)
          :url              url
          :throw-exceptions false
          :headers          (assoc (:headers req)
                                   "Authorization" (auth req))
          :query-params     (get-in req [:resource :query-params])})
        (select-keys [:status :reason-phrase]))))

(defn- path-read
  "This function return data string if found true other wise return false
  INPUT:
  *fs-name*: String, file-system name.
  *dir-array*: list, list of directories to find path nestedly.
  *file-name*: String, file name.
  OUTPUT:
  return body string other wise nil.
  FOR DEBUG: follow up the logs.
  "
  [fs-name dir-arr file-name]
  (let [path (str "/" fs-name "/" (str/join "/" dir-arr) "/" file-name)
        req  (req-obj "GET" {"timestamp" (str (rand-int 1e9))} path)
        url  (uri req)]
    (-> (http/get url
                  {:throw-exceptions false
                   :accept           :json
                   :headers          (assoc (:headers req)
                                            "Authorization" (auth req))
                   :query-params     (get-in req [:resource :query-params])})
        (select-keys [:status :reason-phrase :body]))
    ))

(defn file-read
  "This function read the data if it exist at the path provided to it and return
    content of it otherwise return it false. "
  [path]
  (let [path-arr (destruct-path path)
        fs-name (first path-arr)
        file-name (last path-arr)
        dir-arr (-> path-arr rest butlast vec)]
    (path-read fs-name dir-arr file-name)))

(defn file-create
  "This function create or replace the file with the data provided to it.
   It perform 7 operation in sequence :
   1. Destruct the path
   2. Create fs if not exist
   3. Create nested directories if not exist.
   4. Perform a delete operation to ensure there must not be any exisiting file
      of same name.
      NOTE: we can optimize this step by using list operation but list will create
            big nested tree which is not feasible in our case.
   5. Create file
   6. Append data into the file 
   7. Flush data into the file.
  INPUT:
  *path*: string, in form /plantID/year/day.csv
  *data*: string
  OUTPUT:
  return true if it perform all the task otherwise false.
  For DEBUG: follow up the logs of debug level.
  "
  [path data]
  (let [path-arr (destruct-path path)
        fs-name (first path-arr)
        file-name (last path-arr)
        dir-arr (-> path-arr rest butlast vec)]
    (do
      (fs-create fs-name)
      (path-create-dir fs-name dir-arr)
      (path-delete-file fs-name dir-arr file-name)
      (path-create-file fs-name dir-arr file-name)
      (->> (path-update-append fs-name dir-arr file-name data)
           (path-update-flush fs-name dir-arr file-name))
      )))

(defn file-append
  "This function create the file with data provided to it.
   or if file already exist then it append the data into that file.
   It perform 6 operation in sequence :
   1. Destruct the path
   2. read the file at the given path using path-read.
   3. if path-read true then
      3.1 append the data into the file
      3.2 flush the data.
   4. if path-read fail then
      4.1 create fs if not exist
      4.2 create dir if not exist
      4.3 create file.
      4.4 append data
      4.5 flush the data.
  INPUT:
  *path*: string, in form /plantID/year/day.csv
  *data*: string
  OUTPUT:
  return true if it perform all the task otherwise false.
  For DEBUG: follow up the logs of debug level.
  "
  [path data]
  (let [path-arr (destruct-path path)
        fs-name (first path-arr)
        file-name (last path-arr)
        dir-arr (-> path-arr rest butlast vec)
        file-data (path-read fs-name dir-arr file-name)]
    (if file-data
      (->> (count file-data)
           (path-update-append fs-name dir-arr file-name data)
           (path-update-flush fs-name dir-arr file-name))
      (do
        (fs-create fs-name)
        (path-create-dir fs-name dir-arr)
        (path-create-file fs-name dir-arr file-name)
        (->> (path-update-append fs-name dir-arr file-name data)
             (path-update-flush fs-name dir-arr file-name)))
      )))






(comment
  (def az-key "bB832/nO0qD/+Ao/eLfe1ST0oO72ws6mTlfdJTaGkgCIM/lCaqetdG6VIPfUK4DtziE1In7Q8m0nj7oJLLu+KQ==")

  (def az-account "testazdlsg2")

  (def az-dns-suffix "dfs.core.windows.net")

  @config
  (init-dl az-account az-key az-dns-suffix)

  )
