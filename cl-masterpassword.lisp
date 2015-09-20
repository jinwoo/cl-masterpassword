(in-package #:cl-masterpassword)

(deftype octet () '(unsigned-byte 8))
(deftype octets () '(vector octet))
(deftype uint32 () '(unsigned-byte 32))
(deftype template-type () '(member :maximum :long :medium :short :basic :pin))

(defun string->octets (string)
  (declare (string string))
  (babel:string-to-octets string))

(defun uint32->octets (value)
  (declare (uint32 value))
  (ironclad:integer-to-octets value :n-bits 32))

(defparameter *password-scope* (string->octets "com.lyndir.masterpassword"))
(defparameter *kdf* (ironclad:make-kdf 'ironclad:scrypt-kdf :n 32768 :r 8 :p 2)
  "Key derivation function.")
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

(defun master-key (full-name master-password)
  (declare (string full-name master-password))
  (let ((salt (concatenate 'octets
                           *password-scope*
                           (uint32->octets (length full-name))
                           (string->octets full-name)))
        (password (string->octets master-password)))
    (ironclad:derive-key *kdf* password salt 0 *key-length*)))

(defun seed (master-key site-name site-counter)
  (declare (octets master-key) (string site-name) (uint32 site-counter))
  (let ((hmac (ironclad:make-hmac master-key :sha256)))
    (ironclad:update-hmac hmac *password-scope*)
    (ironclad:update-hmac hmac (uint32->octets (length site-name)))
    (ironclad:update-hmac hmac (string->octets site-name))
    (ironclad:update-hmac hmac (uint32->octets site-counter))
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
