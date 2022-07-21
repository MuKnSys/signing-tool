(defsystem "s2j"
  :depends-on ("cl-json")
  :components ((:file "package")
               (:file "wispym" :depends-on ("package"))
               (:file "wispym2" :depends-on ("package"))
               (:file "sexp-to-json" :depends-on ("package" "wispym"
                                                  "wispym2"))))
