;;; 1password.el --- Retrive password from 1Password  -*- lexical-binding: t; -*-

;; Copyright (C) 2019  Xu Chunyang

;; Author: Xu Chunyang <mail@xuchunyang.me>
;; Homepage: https://github.com/xuchunyang/1password.el
;; Package-Requires: ((emacs "25.1"))
;; Created: 2019年5月15日 晚饭后

;; Author: Henrique Goncalves <kamus@hadenes.io>
;; Updated: 2023-05-09

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; This package needs the command op, it is the 1Password command line tool
;; <https://support.1password.com/command-line/>.

;;; Code:

;; The macro `let-alist' is already autoloaded, this expression is not
;; needed. However, for Emacs without let-alist.el, this expression fails
;; immediately and produces a clean reason.
(eval-when-compile (require 'let-alist))

(require 'json)
(require 'auth-source)

(defvar 1password--get-item-cache nil
  "Cache for `1password-get-item'.

1Password is soooooo slow from here.")

(defgroup 1password nil
  "Use 1Password from Emacs."
  :group 'tools)

(defcustom 1password-op-executable "op"
  "The 1Password command-line tool."
  :group '1password
  :type 'string)

(defvar 1password--session-token nil
  "Stores the session token from 1password-manual-signin")

(defun 1password-manual-signin (password)
    "Prompt for a password, sign into 1password, and then set 1password--session-token with the resulting password"
    (interactive (list (read-passwd "1password password: ")))
    (let
        ((token (with-temp-buffer
                  (if (zerop (call-process-region password nil 1password-op-executable nil t nil "signin" "--raw"))
                      (buffer-string)
                    (error "'op signin --raw' failed: %s" (buffer-string))))))
      (setq 1password--session-token token)
      (message "Saved 1password session token")))

(defun 1password--call-op (&rest args)
  "Execute op with args"
  (let* ((session-args (if 1password--session-token `("--session" ,1password--session-token) nil)))
    (apply 'call-process 1password-op-executable nil t nil (append args session-args))))

(defun 1password--json-read (string)
  "Read JSON from STRING."
  (condition-case err
      (json-parse-string string)
    (error
     (error "JSON parsing error: %s" (error-message-string err)))))

;;;###autoload
(defun 1password-list-items ()
  "List all items in 1Password."
  (let ((cached-items (assoc (downcase "*all_items_list*") 1password--get-item-cache)))
    (if cached-items
        (cdr cached-items)
      (with-temp-buffer
        (if (zerop (1password--call-op "item" "list" "--format" "json"))
            (progn
              (goto-char (point-min))
              (let ((items (1password--json-read (buffer-string))))
                (push (cons (downcase "*all_items_list*") items) 1password--get-item-cache)
                items))
          (error "'op item list' failed: %s" (buffer-string)))))))

;;;###autoload
(defun 1password-get-item (name)
  "Return json object for the NAME item."
  (let ((cached-item (assoc (downcase name) 1password--get-item-cache)))
    (if cached-item
        (cdr cached-item)
      (with-temp-buffer
        (if (zerop (1password--call-op "item" "get" name "--format" "json"))
            (progn
              (goto-char (point-min))
              (let ((item (1password--json-read (buffer-string))))
                (push (cons (downcase name) item) 1password--get-item-cache)
                item))
          (error "'op item get' failed: %s" (buffer-string)))))))

(defun 1password-get-fields (name)
  "Return the fields of the 1Password item with the given NAME."
  (let ((item (1password-get-item name)))
    (when (string= "" name)
      (user-error "Name can't be empty"))
    (append (gethash "fields" item) nil)))

;;;###autoload
(defun 1password-get-field (name field &optional copy)
  "Return the value of the specified FIELD in the 1Password item with the given NAME."
  (when (string= "" name)
    (user-error "Name can't be empty"))
  (when (string= "" field)
    (user-error "Field can't be empty"))
  (let ((fields (1password-get-fields name)))
    (catch 'getfield
      (dolist (field-item fields)
        (let ((field-label (gethash "label" field-item))
              (field-value (gethash "value" field-item)))
          (when (string= field field-label)
            (when copy
              (kill-new field-value)
              (message "Field %s of %s copied: %s" field name field-value))
            (throw 'getfield field-value))))
      (error "Field '%s' not found in item '%s'" field name))))

;;;###autoload
(defun 1password-get-password (name &optional copy)
  "Return password of the NAME item."
  (1password-get-field name "password" copy))

;;;###autoload
(defun 1password-search (field value)
  "Search for item having VALUE in FIELD in 1Password."
  (when (string= "" field)
    (user-error "Field can't be empty"))
  (when (string= "" value)
    (user-error "Value can't be empty"))
  (let
      ((matched-items
        (let ((items (1password-list-items))
              (case-fold-search t))
          (cl-remove-if-not (lambda (item) (string-match-p value (gethash field item))) items))))
    (mapcar
     (lambda (item)
       (let ((item-fields (1password-get-fields (gethash "id" item)))
             (item-hash (make-hash-table :test 'equal)))
         (puthash "host" (gethash "title" item) item-hash)
         (dolist (field-item item-fields)
           (let ((field-label (gethash "label" field-item))
                 (field-value (gethash "value" field-item)))
             (when (string= field-label "api_key")
               (puthash "api_key" field-value item-hash))
             (when (string= field-label "password")
               (puthash "secret" field-value item-hash))
             (when (string= field-label "email")
               (puthash "login" field-value item-hash)
               (puthash "user" field-value item-hash))
             (when (string= field-label "username")
               (puthash "login" field-value item-hash)
               (puthash "user" field-value item-hash))))
         item-hash))
     matched-items)))

(defun 1password-search-filter-username (accounts &optional username)
  "Filter results of `1password-search' ACCOUNTS by USERNAME.
ACCOUNTS can be the results of `1password-search' or a string to
search which will call `1password-search' as a convenience."
  (let* ((accounts (if (vectorp accounts)
                       accounts (1password-search "title" accounts)))
         ;; filter out matches that are not logins
         (accounts (seq-filter (lambda (elt) (gethash "login" elt)) accounts)))
    (if (and (stringp username) (not (string= username "")))
        (seq-filter (lambda (elt)
                      (when-let ((login (gethash "login" elt)))
                        (string= login username)))
                    accounts)
      accounts)))

;;================================= auth-source =================================

(defun 1password-auth-source-search (&rest spec)
  "Search 1Password according to SPEC.
See `auth-source-search' for a description of the plist SPEC."
  (let* ((host (plist-get spec :host))
         (max (plist-get spec :max))
         (user (plist-get spec :user))
         (res (mapcar #'1password-auth-source--build-result
                      (1password-search-filter-username host user))))
    (seq-take res max)))

(defun 1password-auth-source--build-result (elt)
  "Build a auth-source result for ELT.
This is meant to be used by `mapcar' for the results from
`1password-search-filter-username'."
  (let ((l '()))
    (maphash
     (lambda (key value)
       (setq l (cons (cons (intern (concat ":" key)) value) l )))
     elt)
    (flatten-tree l)))

(defvar 1password-auth-source-backend
  (auth-source-backend :type '1password
                       :source "." ;; not used
                       :search-function #'1password-auth-source-search)
  "Auth-source backend variable for 1Password.")

(defun 1password-auth-source-backend-parse (entry)
  "Create auth-source backend from ENTRY."
  (when (eq entry '1password)
    (auth-source-backend-parse-parameters entry 1password-auth-source-backend)))

;; advice to add custom auth-source function
(if (boundp 'auth-source-backend-parser-functions)
    (add-hook 'auth-source-backend-parser-functions
              #'1password-auth-source-backend-parse)
  (advice-add 'auth-source-backend-parse
              :before-until #'1password-auth-source-backend-parse))

;;;###autoload
(defun 1password-auth-source-enable ()
  "Enable 1password auth-source by adding it to `auth-sources'."
  (interactive)
  (add-to-list 'auth-sources '1password)
  (auth-source-forget-all-cached)
  (message "1Password: auth-source enabled"))

(provide '1password)
;;; 1password.el ends here
