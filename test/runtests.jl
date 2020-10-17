using SparseMerkleTree
using BitIntegers
using Test

@testset "SparseMerkleTree.jl" begin
    db = new_tree()
    @test db.root == SparseMerkleTree.Hash(parse(UInt256, "0x876422b7697ae7c337e2ee7727feb3db474adf7be1cf04b6b5857d82d610e88a"))

    k = UInt256(200)
    v = Vector{UInt8}(b"foo")
    db[k] = v
    @test db.root == Hash(parse(UInt256, "0x108b52f48b1d7f361359def8c726f1b6256de9e2b41e363e9604ce0556e3fb2d"))

    p1 = merkle_proof(db, k)
    @test verify_proof(p1, db.root, k, v)

    k = UInt256(0xabababab000ffffccccc)
    v = Vector{UInt8}(b"bar")
    db[k] = v
    @test db.root == Hash(parse(UInt256, "0x973de6aec749609fa159cb96f53e2b130f9280faefa16bf61ef97915da4401f6"))

    p2 = merkle_proof(db, k)
    @test verify_proof(p2, db.root, k, v)

    p3 = compress_proof(p2)
    p4 = decompress_proof(p3)
    @test p2 == p4
    @test verify_proof(p4, db.root, k, v)
end
