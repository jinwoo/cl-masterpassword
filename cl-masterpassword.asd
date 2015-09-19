(asdf:defsystem #:cl-masterpassword
  :description "Common Lisp version of Master Password"
  :author "Jinwoo Lee"
  :license "MIT"
  :depends-on (#:babel
               #:ironclad)
  :serial t
  :components ((:file "package")
               (:file "cl-masterpassword")))
