; extracts from wispym lib
; Copyright Vibhu Mohindra
; Licence: This file may be used and redistributed as you wish,
;          provided only that its owner is given your improvements.
(defparameter *eof* (gensym))
(defun slurp-exprs (file)
  (with-open-file (s file)
    (do ((defs nil)
         (def (read s nil *eof*) (read s nil *eof*)))
        ((eql def *eof*) (reverse defs))
      (push def defs))))
(defun append-expr (expr file)
  (with-open-file (out file
                       :direction :output
                       :if-exists :append
                       :if-does-not-exist :create)
    (pprint expr out)))
