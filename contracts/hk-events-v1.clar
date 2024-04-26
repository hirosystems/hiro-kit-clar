(define-map events { event-hash: (buff 32) } { event: (buff 4096) } )

;; @desc 
(define-public (store (topic (string-ascii 64)) (payload (buff 2048)) (accumulator { events: (list 64 (buff 2048)), nonce: uint }))
  (let ((event { 
          contract: contract-caller, 
          topic: topic, 
          payload: payload, 
          block-height: block-height, 
          parent-block-hash: (get-block-info? header-hash (- block-height u1)), 
          tx-sender: tx-sender, 
          tx-sponsor: tx-sponsor?,
          nonce: (get nonce accumulator)
        })
          (encoded-event (unwrap-panic (to-consensus-buff? event))))
    (map-insert events { event-hash: (sha256 encoded-event) } { event: encoded-event })
    (ok true)))

