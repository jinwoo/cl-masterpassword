(in-package #:cl-masterpassword)

(defparameter *password-scope* "com.lyndir.masterpassword")
(defparameter *key-n* 32768)
(defparameter *key-r* 8)
(defparameter *key-p* 2)
(defparameter *key-length* 64)

(defparameter *templates*
  '((:maximum . #("anoxxxxxxxxxxxxxxxxx"
                  "axxxxxxxxxxxxxxxxxno"))
    (:long . #("CvcvnoCvcvCvcv"
               "CvcvCvcvnoCvcv"
               "CvcvCvcvCvcvno"
               "CvccnoCvcvCvcv"
               "CvccCvcvnoCvcv"
               "CvccCvcvCvcvno"
               "CvcvnoCvccCvcv"
               "CvcvCvccnoCvcv"
               "CvcvCvccCvcvno"
               "CvcvnoCvcvCvcc"
               "CvcvCvcvnoCvcc"
               "CvcvCvcvCvccno"
               "CvccnoCvccCvcv"
               "CvccCvccnoCvcv"
               "CvccCvccCvcvno"
               "CvcvnoCvccCvcc"
               "CvcvCvccnoCvcc"
               "CvcvCvccCvccno"
               "CvccnoCvcvCvcc"
               "CvccCvcvnoCvcc"
               "CvccCvcvCvccno"))
    (:medium . #("CvcnoCvc"
                 "CvcCvcno"))
    (:short . #("Cvcn"))
    (:basic . #("aaanaaan"
                "aannaaan"
                "aaannaaa"))
    (:pin . #("nnnn"))))

(defparameter *password-characters*
  '((#\V . "AEIOU")
    (#\C . "BCDFGHJKLMNPQRSTVWXYZ")
    (#\v . "aeiou")
    (#\c . "bcdfghjklmnpqrstvwxyz")
    (#\A . "AEIOUBCDFGHJKLMNPQRSTVWXYZ")
    (#\a . "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz")
    (#\n . "0123456789")
    (#\o . "@&%?,=[]_:-+*$#!'^~;()/.")
    (#\x . "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()")))

(deftype octet () '(unsigned-byte 8))
(deftype octets () '(vector octet))
(deftype int32 () '(unsigned-byte 32))
(deftype template-type () '(member :maximum :long :medium :short :basic :pin))

(defun string->octets (string)
  (declare (string string))
  (babel:string-to-octets string))

(defun int32->octets (value)
  (declare (int32 value))
  (ironclad:integer-to-octets value :n-bits 32))

(defun master-key (full-name master-password)
  (declare (string full-name master-password))
  (let ((salt (concatenate 'octets
                           (string->octets *password-scope*)
                           (int32->octets (length full-name))
                           (string->octets full-name)))
        (password (string->octets master-password))
        (kdf (ironclad:make-kdf 'ironclad:scrypt-kdf :n *key-n*
                                                     :r *key-r*
                                                     :p *key-p*)))
    (ironclad:derive-key kdf password salt 0 *key-length*)))

(defun seed (master-key site-name site-counter)
  (declare (octets master-key) (string site-name) (int32 site-counter))
  (let ((hmac (ironclad:make-hmac master-key :sha256)))
    (ironclad:update-hmac hmac (string->octets *password-scope*))
    (ironclad:update-hmac hmac (int32->octets (length site-name)))
    (ironclad:update-hmac hmac (string->octets site-name))
    (ironclad:update-hmac hmac (int32->octets site-counter))
    (ironclad:hmac-digest hmac)))

(defun template (seed type)
  (declare (octets seed) (template-type type))
  (let ((candidates (cdr (assoc type *templates* :test #'eq))))
    (aref candidates (mod (aref seed 0) (length candidates)))))

(defun password-character (class seed-byte)
  (declare (character class) (octet seed-byte))
  (let ((choices (cdr (assoc class *password-characters*))))
    (aref choices (mod seed-byte (length choices)))))

(defun password (seed type)
  (declare (octets seed) (template-type type))
  (coerce (loop for c across (template seed type)
                for i from 1
                collect (password-character c (aref seed i)))
          'string))
