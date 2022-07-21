;;;; helps expand config.in into a structure requiring less processing in Go.
;;;; you still need to convert the output of this function to json yourself.

;;;; (load "wispym")
;;;; (load "hostcomp")
;;;; (expand-config "../siggy/config.in" "/tmp/config.tmp")
;;;; and then translate /tmp/config.tmp from sexpr to json (e.g. using s2j)

;;; public keys must all be distinct, as must their filenames be
;;; a member may only be in one host
(defun expand-config (infile outfile)
  (let ((entries (cdr (assoc 'hosts (slurp-exprs infile)))))
    (let ((labels (mapcar #'car entries))
          (addrs (mapcar #'cadr entries))
          (members (mapcar #'caddr entries)))
      (append-expr
        (list labels addrs members (mapcan #'copy-list members))
        outfile))))
