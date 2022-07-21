(in-package "S2J")

; extracts from wispym2 lib
; Licence:
; This file may be used and redistributed as you wish,
; provided only that Wispym is granted ownership of your improvements.

;call this function to
;improve cl-json to print nil as [] instead of null.
;that simplifies higher level protocol parsers in other languages.

;never matched by decoder. so works even with clos semantics where
;json arrays are parsed into lisp vectors not lists.
(defun cl-json-print-nil-as-list ()
  (pushnew '("[]" . nil) cl-json::+json-lisp-symbol-tokens+ :test #'equal))
