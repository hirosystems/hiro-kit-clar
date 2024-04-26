(define-map events { event-hash: (buff 32) } { event-bytes: (buff 4096) } )

;; @desc 
(define-public (store (topic (string-ascii 64)) (payload (buff 2048)) (accumulator { events-hashes: (list 128 (buff 32)) }))
  (let ((event (build-accumulated-event topic payload accumulator)))
    (print { data: (get data event), hash: (get hash event) })
    (map-insert events { event-hash: (get hash event) } { event-bytes: (get bytes event) })
    (ok event)))

;; @desc 
(define-read-only (emit (topic (string-ascii 64)) (payload (buff 2048)) (accumulator { events-hashes: (list 128 (buff 32)) }))
  (let ((event (build-accumulated-event topic payload accumulator)))
    (print { data: (get data event), hash: (get hash event) })
    (ok event)))

;; @desc 
(define-private (build-accumulated-event (topic (string-ascii 64)) (payload (buff 2048)) (accumulator { events-hashes: (list 128 (buff 32)) }))
  (let ((nonce (len (get events-hashes accumulator)))
        (data { 
          contract: contract-caller, 
          topic: topic, 
          payload: payload, 
          block-height: block-height, 
          parent-block-hash: (get-block-info? header-hash (- block-height u1)), 
          tx-sender: tx-sender, 
          tx-sponsor: tx-sponsor?,
          nonce: nonce
        })
          (bytes (unwrap-panic (to-consensus-buff? data)))
          (hash (sha256 bytes))
          (updated-accumulator (unwrap-panic (as-max-len? (append (get events-hashes accumulator) hash) u128))))
    { data: data, bytes: bytes, hash: hash, accumulator: updated-accumulator }))

