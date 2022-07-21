#!/bin/bash

# adapted from a previous project of mine

# builds executable file from lisp source code
# prerequisites: clisp, quicklisp (set up to autoload into clisp session)
# output: executable file s2j

clisp -q -ansi \
      -x '(push #p"./" asdf:*central-registry*)' \
      -x '(ql:quickload "s2j")' \
      -x "(defun clisp-main ()
            (apply #'s2j:translate-file ext:*args*)
            (ext:exit))" \
      -x '(ext:saveinitmem "s2j" :quiet t :norc t :executable t
                             :init-function (quote clisp-main))'
