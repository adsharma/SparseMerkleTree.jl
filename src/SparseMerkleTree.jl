module SparseMerkleTree

# Based on a slightly modified version of vbuterins new_bin_trie.py

using MLStyle
using SHA
using BitIntegers

import Base.getindex
import Base.setindex!

# Assumes system is little endian
function from_bytes(b)::UInt256
    reinterpret(UInt256, reverse(b))[1]
end

# In system byte order
function to_bytes(b)
    reinterpret(UInt8, [b])
end

function to_bytes(b::Array{UInt8})
    b
end

struct Hash
    value::UInt256
end

function Base.:(==)(x::Hash, y::Hash)
    x.value == y.value
end

function Base.:+(x::Hash, y::Hash)
    bytes = map(to_bytes, (x.value, y.value))
    bytes = map(reverse, bytes)
    Hash(from_bytes(sha256(vcat(bytes[1], bytes[2]))))
end

zerohashes = [Hash(from_bytes(sha256(repeat(b"\0", 32))))]
for i in 1:256
    insert!(zerohashes, 1, zerohashes[1] + zerohashes[1])
end

NodeValue = Array{Array{UInt8, 1}, 1}  # Array of 2 elements with child hashes
LeafValue = Array{UInt8}

mutable struct SMT
    db::Dict{UInt256, Union{NodeValue, LeafValue}}
    root::Hash
end

function new_tree()
    smt = SMT(Dict(), Hash(0))
    db = smt.db
    h = sha256(repeat(b"\0", 32))
    for i in 1:256
        hh = vcat(h, h)
        newh = sha256(hh)
        db[from_bytes(newh)] = [h, h]
        h = newh
    end
    smt.root = Hash(from_bytes(h))
    return smt
end

function getindex(smt::SMT, k::Hash)
    x = smt.db[k.value]
    @match x begin
    nothing => nothing
    [a, b] => (from_bytes(a), from_bytes(b))
    end
end

function bitmask(n::UInt256)
    x = BitVector(undef, 256)
    n_chunks = reinterpret(UInt64, [n])
    for (i, ch) in enumerate(n_chunks)
        x.chunks[i] = ch
    end
    x
end

function getindex(smt::SMT, k::UInt256)
    s = bitmask(k)
    v = smt.root
    for b in s
        v = @match b begin
        false => Hash(smt[v][1])
        true  => Hash(smt[v][2])
        end
    end
    return v
end

struct Proof
    sidenodes
    zero_bitmask
end

function merkle_proof(smt::SMT, k::UInt256)
    # Iterate the tree top down and compute sidenodes
    s = reverse(bitmask(k))
    cur = smt.root
    sidenodes = []
    for b in s
        children = smt[cur]
        cur, side = @match b begin
        true  => Hash.(reverse(children))
        false => Hash.(children)
        end
        append!(sidenodes, side.value)
    end
    return Proof(Hash.(sidenodes), 0)
end

function setindex!(smt::SMT, v::V, k::UInt256) where V
    sidenodes = merkle_proof(smt, k).sidenodes
    # Iterate the tree bottom up updating hashes
    cur = to_bytes(v)
    curhash = Hash(from_bytes(sha256(cur)))
    smt.db[curhash.value] = v
    for b in bitmask(k)
        side = last(sidenodes)
        newh, left, right = @match b begin
        true => (side + curhash, side, curhash)
        false => (curhash + side, curhash, side)
        end
        smt.db[newh.value] = [reverse(to_bytes(left.value)), reverse(to_bytes(right.value))]
        pop!(sidenodes)
        curhash = newh
    end
    smt.root = curhash
end

function verify_proof(proof::Proof, root, k, v)
    sidenodes = reverse(proof.sidenodes)
    # Iterate the tree bottom up updating hashes
    cur = to_bytes(v)
    curhash = Hash(from_bytes(sha256(cur)))
    for (i, b) in enumerate(bitmask(k))
        side = sidenodes[i]
        newh, left, right = @match b begin
        true => (side + curhash, side, curhash)
        false => (curhash + side, curhash, side)
        end
        curhash = newh
    end
    return root.value == curhash.value
end

function compress_proof(proof)
    sidenodes = proof.sidenodes
    mask = (sidenodes .== zerohashes[2:end])
    compressed = []
    for (i, b) in enumerate(mask)
        if b == false
            append!(compressed, sidenodes[i].value)
        end
    end
    Proof(Hash.(compressed), mask)
end

function decompress_proof(proof)
    j = 1
    sidenodes = proof.sidenodes
    decompressed = []
    for (i, b) in enumerate(proof.zero_bitmask)
        if b == false
            append!(decompressed, sidenodes[j].value)
            j += 1
        else
            append!(decompressed, zerohashes[i+1].value)
        end
    end
    Proof(Hash.(decompressed), 0)
end

db = new_tree()
println(db.root)
k = UInt256(200)
v = Vector{UInt8}(b"foo")
db[k] = v
println(db.root)
p1 = merkle_proof(db, k)
println(verify_proof(p1, db.root, k, v))
k = UInt256(0xabababab000ffffccccc)
v = Vector{UInt8}(b"bar")
db[k] = v
p2 = merkle_proof(db, k)
p3 = compress_proof(p2)
p4 = decompress_proof(p3)
println(db.root)
println(verify_proof(p4, db.root, k, v))

end
