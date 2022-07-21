(in-package "S2J")

(cl-json-print-nil-as-list)

(defun translate-file (input output)
  (dump-to-file
    (pr-separated #\Newline
                  (mapcar #'encode-json-to-string
                          (let ((*read-eval* nil)) (slurp-exprs input))))
    output))
