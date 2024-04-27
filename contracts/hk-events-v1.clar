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

(define-read-only (compute-merkle-proof (accumulator { events-hashes: (list 128 (buff 32)) }))
  (let ((layer-1 (hash-layer-128 (get events-hashes accumulator)))
        (layer-2 (hash-layer-64 layer-1))
        (layer-3 (hash-layer-32 layer-2))
        (layer-4 (hash-layer-16 layer-3))
        (layer-5 (hash-layer-8 layer-4))
        (layer-6 (hash-layer-4 layer-5))
        (layer-7 (hash-layer-2 layer-6)))
      (ok { 
        layer-1: layer-1,
        layer-2: layer-2,
        layer-3: layer-3,
        layer-4: layer-4,
        layer-5: layer-5,
        layer-6: layer-6,
        layer-7: layer-7
      })))

(define-private (hash-layer-128 (hashes (list 128 (buff 32))))
  (unwrap-panic (as-max-len? (get hashes (fold pair-nodes hashes {
        cursor: u0,
        pairs: (list), 
        hashes: (list), 
        limit: u64
      })) u64)))

(define-private (hash-layer-64 (hashes (list 64 (buff 32))))
  (unwrap-panic (as-max-len? (get hashes (fold pair-nodes hashes {
        cursor: u0,
        pairs: (list), 
        hashes: (list), 
        limit: u32
      })) u32)))

(define-private (hash-layer-32 (hashes (list 32 (buff 32))))
  (unwrap-panic (as-max-len? (get hashes (fold pair-nodes hashes {
        cursor: u0,
        pairs: (list), 
        hashes: (list), 
        limit: u16
      })) u16)))

(define-private (hash-layer-16 (hashes (list 16 (buff 32))))
  (unwrap-panic (as-max-len? (get hashes (fold pair-nodes hashes {
        cursor: u0,
        pairs: (list), 
        hashes: (list), 
        limit: u8
      })) u8)))

(define-private (hash-layer-8 (hashes (list 8 (buff 32))))
  (unwrap-panic (as-max-len? (get hashes (fold pair-nodes hashes {
        cursor: u0,
        pairs: (list), 
        hashes: (list), 
        limit: u4
      })) u4)))

(define-private (hash-layer-4 (hashes (list 4 (buff 32))))
  (unwrap-panic (as-max-len? (get hashes (fold pair-nodes hashes {
        cursor: u0,
        pairs: (list), 
        hashes: (list), 
        limit: u2
      })) u2)))

(define-private (hash-layer-2 (hashes (list 2 (buff 32))))
  (unwrap-panic (as-max-len? (get hashes (fold pair-nodes hashes {
        cursor: u0,
        pairs: (list), 
        hashes: (list), 
        limit: u1
      })) u1)))

(define-private (pair-nodes
      (node (buff 32)) 
      (acc { 
        cursor: uint,
        pairs: (list 64 (list 2 (buff 32))), 
        hashes: (list 32 (buff 32)), 
        limit: uint
      }))
  (if (is-eq (len (get hashes acc)) (get limit acc))
    acc
    {
      cursor: (+ (get cursor acc) u1),
      pairs: (if (is-eq (mod (get cursor acc) u2) u0)
        (unwrap-panic (as-max-len? (append (get pairs acc) (list node)) u64))
        (unwrap-panic (replace-at? 
          (get pairs acc) 
          (/ (get cursor acc) u2)
          (unwrap-panic (as-max-len? (append (unwrap-panic (element-at? (get pairs acc) (/ (get cursor acc) u2))) node) u2))))),
      hashes: (if (is-eq (mod (get cursor acc) u2) u0)
        (get hashes acc)
        (unwrap-panic (as-max-len? (append (get hashes acc) (hash-nodes (unwrap-panic (element-at? (get pairs acc) (/ (get cursor acc) u2))))) u32))),
      limit: (get limit acc),
    }))

(define-private (hash-nodes (pair (list 2 (buff 32))))
  (sha256 (concat (unwrap-panic (element-at? pair u0)) (unwrap-panic (element-at? pair u1)))))

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
          nonce: nonce,
          chain-id: chain-id,
        })
          (bytes (unwrap-panic (to-consensus-buff? data)))
          (hash (sha256 bytes))
          (updated-accumulator (unwrap-panic (as-max-len? (append (get events-hashes accumulator) hash) u128))))
    { data: data, bytes: bytes, hash: hash, accumulator: updated-accumulator }))

