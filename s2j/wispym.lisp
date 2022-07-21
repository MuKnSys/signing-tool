(in-package "S2J")

; extracts from wispym lib
; Licence:
; This file may be used and redistributed as you wish,
; provided only that Wispym is granted ownership of your improvements.

(defun dump-to-file (text filename)
  (with-open-file (f filename :direction :output :if-exists :supersede)
    (write-string text f)))
(defparameter *eof* (gensym))
(defun slurp-exprs (file)
  (with-open-file (s file)
    (do ((defs nil)
         (def (read s nil *eof*) (read s nil *eof*)))
        ((eql def *eof*) (reverse defs))
      (push def defs))))
(defun pr-separated (sep vals)
  (if vals
    (with-output-to-string (s)
      (princ (car vals) s)
      (mapc #'(lambda (v)
                (princ sep s)
                (princ v s))
            (cdr vals)))
    ""))
