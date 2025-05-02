-- 文件名：dtlcp.lua

-- 定义新的协议
dtlcp = Proto("dtlcp", "DTLCP Protocol")

-- 定义字段
local f_content_type = ProtoField.uint8("dtlcp.content_type", "Content Type", base.DEC, {
    [20] = "Change Cipher Spec",
    [21] = "Alert",
    [22] = "Handshake",
    [23] = "Application Data",
    [255] = "Reserved"
})
local f_version = ProtoField.uint16("dtlcp.version", "Version", base.HEX)
local f_epoch = ProtoField.uint16("dtlcp.epoch", "Epoch", base.DEC)
local f_sequence_number = ProtoField.uint64("dtlcp.sequence_number", "Sequence Number", base.DEC)
local f_length = ProtoField.uint16("dtlcp.length", "Length", base.DEC)
local f_payload = ProtoField.bytes("dtlcp.payload", "Payload")

-- 握手协议字段
local f_handshake_type = ProtoField.uint8("dtlcp.handshake.type", "Handshake Type", base.DEC, {
    [0] = "Hello Request",
    [1] = "Client Hello",
    [2] = "Server Hello",
    [3] = "Hello Verify Request",
    [11] = "Certificate",
    [12] = "Server Key Exchange",
    [13] = "Certificate Request",
    [14] = "Server Hello Done",
    [15] = "Certificate Verify",
    [16] = "Client Key Exchange",
    [20] = "Finished",
    [255] = "Reserved"
})

-- CertificateVerify消息字段定义
local f_signature_algorithm = ProtoField.uint8("dtlcp.handshake.signature_algorithm", "Signature Algorithm", base.DEC, {
    [1] = "rsa_sha256",
    [2] = "rsa_sm3",
    [3] = "ecc_sm3",
    [4] = "ibs_sm3"
})
local f_signature_hash_sha256 = ProtoField.bytes("dtlcp.handshake.signature_hash_sha256", "SHA256 Hash")
local f_signature_hash_sm3 = ProtoField.bytes("dtlcp.handshake.signature_hash_sm3", "SM3 Hash")
local f_signature_data = ProtoField.bytes("dtlcp.handshake.signature_data", "Signature Data")
local f_handshake_length = ProtoField.uint24("dtlcp.handshake.length", "Handshake Length", base.DEC)
local f_handshake_seq = ProtoField.uint16("dtlcp.handshake.message_seq", "Message Sequence", base.DEC)
local f_handshake_frag_offset = ProtoField.uint24("dtlcp.handshake.fragment_offset", "Fragment Offset", base.DEC)
local f_handshake_frag_length = ProtoField.uint24("dtlcp.handshake.fragment_length", "Fragment Length", base.DEC)
local f_handshake_body = ProtoField.bytes("dtlcp.handshake.body", "Handshake Body")

-- ClientHello 消息字段定义
local f_client_version = ProtoField.uint16("dtlcp.handshake.client_version", "Client Version", base.HEX)
local f_random_time = ProtoField.uint32("dtlcp.handshake.random_time", "Random Time", base.DEC)
local f_random_bytes = ProtoField.bytes("dtlcp.handshake.random_bytes", "Random Bytes")
local f_session_id_len = ProtoField.uint8("dtlcp.handshake.session_id_len", "Session ID Length", base.DEC)
local f_session_id = ProtoField.bytes("dtlcp.handshake.session_id", "Session ID")
local f_cookie_len = ProtoField.uint8("dtlcp.handshake.cookie_len", "Cookie Length", base.DEC)
local f_cookie = ProtoField.bytes("dtlcp.handshake.cookie", "Cookie")
local f_cipher_suites_len = ProtoField.uint16("dtlcp.handshake.cipher_suites_len", "Cipher Suites Length", base.DEC)
local f_cipher_suite = ProtoField.uint16("dtlcp.handshake.cipher_suite", "Cipher Suite", base.HEX, {
    [0xe011] = "ECDHE_SM4_CBC_SM3",
    [0xe051] = "ECDHE_SM4_GCM_SM3",
    [0xe013] = "ECC_SM4_CBC_SM3",
    [0xe053] = "ECC_SM4_GCM_SM3"
})
local f_compression_methods_len = ProtoField.uint8("dtlcp.handshake.compression_methods_len", "Compression Methods Length", base.DEC)
local f_compression_method = ProtoField.uint8("dtlcp.handshake.compression_method", "Compression Method", base.DEC, {
    [0] = "null",
    [255] = "Reserved"
})

-- ServerHello 消息字段定义
local f_server_version = ProtoField.uint16("dtlcp.handshake.server_version", "Server Version", base.HEX)
local f_server_random = ProtoField.bytes("dtlcp.handshake.server_random", "Server Random")
local f_server_session_id_len = ProtoField.uint8("dtlcp.handshake.server_session_id_len", "Server Session ID Length", base.DEC)
local f_server_session_id = ProtoField.bytes("dtlcp.handshake.server_session_id", "Server Session ID")
local f_server_cipher_suite = ProtoField.uint16("dtlcp.handshake.server_cipher_suite", "Server Cipher Suite", base.HEX, {
    [0xe011] = "ECDHE_SM4_CBC_SM3",
    [0xe051] = "ECDHE_SM4_GCM_SM3",
    [0xe013] = "ECC_SM4_CBC_SM3",
    [0xe053] = "ECC_SM4_GCM_SM3"
})
local f_server_compression_method = ProtoField.uint8("dtlcp.handshake.server_compression_method", "Server Compression Method", base.DEC, {
    [0] = "null",
    [255] = "Reserved"
})

-- Certificate 消息字段定义
local f_certificate_length = ProtoField.uint24("dtlcp.handshake.certificate_length", "Certificate Length", base.DEC)
local f_certificate_data = ProtoField.bytes("dtlcp.handshake.certificate_data", "Certificate Data")

-- IBC标识及公共参数结构字段定义
local f_ibc_id_length = ProtoField.uint16("dtlcp.handshake.ibc_id_length", "IBC ID Length", base.DEC)
local f_ibc_id = ProtoField.bytes("dtlcp.handshake.ibc_id", "IBC ID")
local f_ibc_parameter = ProtoField.bytes("dtlcp.handshake.ibc_parameter", "IBC Parameter")

-- Certificate Request消息字段定义
local f_cert_types_length = ProtoField.uint8("dtlcp.handshake.cert_types_length", "Certificate Types Length", base.DEC)
local f_cert_type = ProtoField.uint8("dtlcp.handshake.cert_type", "Certificate Type", base.DEC, {
    [1] = "rsa_sign",
    [64] = "ecdsa_sign",
    [80] = "ibc_params",
    [255] = "Reserved"
})
local f_cert_authorities_length = ProtoField.uint16("dtlcp.handshake.cert_authorities_length", "Certificate Authorities Length", base.DEC)
local f_cert_authority = ProtoField.bytes("dtlcp.handshake.cert_authority", "Certificate Authority")
local f_cert_authority_length = ProtoField.uint8("dtlcp.handshake.cert_authority_length", "Certificate Authority Length", base.DEC)

-- ServerKey Exchange消息字段定义
local f_key_exchange_algorithm = ProtoField.uint8("dtlcp.handshake.key_exchange_algorithm", "Key Exchange Algorithm", base.DEC, {
    [1] = "ECDHE",
    [2] = "ECC",
    [3] = "IBSDH",
    [4] = "IBC",
    [5] = "RSA"
})
-- ECDHE参数字段
local f_ecdhe_params = ProtoField.bytes("dtlcp.handshake.ecdhe_params", "ECDHE Parameters")
local f_ecdhe_public = ProtoField.bytes("dtlcp.handshake.ecdhe_public", "ECDHE Public Key")
-- IBSDH参数字段
local f_ibsdh_params = ProtoField.bytes("dtlcp.handshake.ibsdh_params", "IBSDH Parameters")
-- IBC参数字段
local f_ibc_params = ProtoField.bytes("dtlcp.handshake.ibc_params", "IBC Parameters")
local f_ibc_encryption_key = ProtoField.bytes("dtlcp.handshake.ibc_encryption_key", "IBC Encryption Key")
-- 签名参数字段
local f_client_random = ProtoField.bytes("dtlcp.handshake.client_random", "Client Random")
local f_ske_server_random = ProtoField.bytes("dtlcp.handshake.ske_server_random", "Server Random")
local f_signed_params = ProtoField.bytes("dtlcp.handshake.signed_params", "Signed Parameters")
local f_asn1_cert = ProtoField.bytes("dtlcp.handshake.asn1_cert", "ASN.1 Certificate")

-- ClientKey Exchange消息字段定义
local f_client_key_exchange_algorithm = ProtoField.uint8("dtlcp.handshake.client_key_exchange_algorithm", "Client Key Exchange Algorithm", base.DEC, {
    [1] = "ECDHE",
    [2] = "ECC",
    [3] = "IBSDH",
    [4] = "IBC",
    [5] = "RSA"
})
-- ECDHE客户端参数字段
local f_client_ecdhe_params = ProtoField.bytes("dtlcp.handshake.client_ecdhe_params", "Client ECDHE Parameters")
local f_client_ecdhe_public = ProtoField.bytes("dtlcp.handshake.client_ecdhe_public", "Client ECDHE Public Key")
-- IBSDH客户端参数字段
local f_client_ibsdh_params = ProtoField.bytes("dtlcp.handshake.client_ibsdh_params", "Client IBSDH Parameters")
-- 加密的预主密钥字段
local f_ecc_encrypted_pms = ProtoField.bytes("dtlcp.handshake.ecc_encrypted_pms", "ECC Encrypted PreMaster Secret")
local f_ibc_encrypted_pms = ProtoField.bytes("dtlcp.handshake.ibc_encrypted_pms", "IBC Encrypted PreMaster Secret")
local f_rsa_encrypted_pms = ProtoField.bytes("dtlcp.handshake.rsa_encrypted_pms", "RSA Encrypted PreMaster Secret")
-- 预主密钥结构字段
local f_pms_client_version = ProtoField.uint16("dtlcp.handshake.pms_client_version", "PreMaster Secret Client Version", base.HEX)
local f_pms_random = ProtoField.bytes("dtlcp.handshake.pms_random", "PreMaster Secret Random Bytes")

-- Finished消息字段定义
local f_verify_data = ProtoField.bytes("dtlcp.handshake.verify_data", "Verify Data")

dtlcp.fields = {
    f_content_type,
    f_version,
    f_epoch,
    f_sequence_number,
    f_length,
    f_payload,
    f_handshake_type,
    f_handshake_length,
    f_handshake_seq,
    f_handshake_frag_offset,
    f_handshake_frag_length,
    f_handshake_body,
    
    -- ClientHello 消息字段
    f_client_version,
    f_random_time,
    f_random_bytes,
    f_session_id_len,
    f_session_id,
    f_cookie_len,
    f_cookie,
    f_cipher_suites_len,
    f_cipher_suite,
    f_compression_methods_len,
    f_compression_method,
    
    -- ServerHello 消息字段
    f_server_version,
    f_server_random,
    f_server_session_id_len,
    f_server_session_id,
    f_server_cipher_suite,
    f_server_compression_method,
    
    -- Certificate 消息字段
    f_certificate_length,
    f_certificate_data,
    f_ibc_id_length,
    f_ibc_id,
    f_ibc_parameter,
    
    -- Certificate Request 消息字段
    f_cert_types_length,
    f_cert_type,
    f_cert_authorities_length,
    f_cert_authority,
    f_cert_authority_length,
    
    -- ServerKey Exchange 消息字段
    f_key_exchange_algorithm,
    f_ecdhe_params,
    f_ecdhe_public,
    f_ibsdh_params,
    f_ibc_params,
    f_ibc_encryption_key,
    f_client_random,
    f_ske_server_random,
    f_signed_params,
    f_asn1_cert,
    
    -- ClientKey Exchange 消息字段
    f_client_key_exchange_algorithm,
    f_client_ecdhe_params,
    f_client_ecdhe_public,
    f_client_ibsdh_params,
    f_ecc_encrypted_pms,
    f_ibc_encrypted_pms,
    f_rsa_encrypted_pms,
    f_pms_client_version,
    f_pms_random,
    
    -- CertificateVerify 消息字段
    f_signature_algorithm,
    f_signature_hash_sha256,
    f_signature_hash_sm3,
    f_signature_data,
    
    -- Finished 消息字段
    f_verify_data
}

-- 用于存储分片的全局表
local fragments = {}

-- 分片重组函数
local function reassemble_fragments(msg_type, msg_seq, fragments_table)
    -- 按照偏移量排序分片
    table.sort(fragments_table, function(a, b) return a.offset < b.offset end)
    
    -- 检查分片是否连续
    local expected_offset = 0
    local total_length = 0
    
    for _, fragment in ipairs(fragments_table) do
        if fragment.offset ~= expected_offset then
            -- 分片不连续，有缺失
            return nil
        end
        expected_offset = fragment.offset + fragment.length
        total_length = total_length + fragment.length
    end
    
    -- 创建一个新的tvb来存储重组后的消息
    local reassembled = ByteArray.new()
    for _, fragment in ipairs(fragments_table) do
        reassembled:append(fragment.data:bytes())
    end
    
    return reassembled, total_length
end

-- 协议解析函数
function dtlcp.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = dtlcp.name
    
    -- 初始化info列信息
    local info_items = {}
    
    local offset = 0
    while offset + 13 <= buffer:len() do
        local content_type = buffer(offset,1)
        local version = buffer(offset+1,2)
        local epoch = buffer(offset+3,2)
        local seq_num = buffer(offset+5,6)
        local length = buffer(offset+11,2)
        local len = length:uint()

        if offset + 13 + len > buffer:len() then
            tree:add_expert_info(PI_MALFORMED, PI_ERROR, "DTLCP record claims length beyond buffer size")
            break
        end

        local subtree = tree:add(dtlcp, buffer(offset, 13 + len), "DTLCP Record")
        subtree:add(f_content_type, content_type)
        subtree:add(f_version, version)
        subtree:add(f_epoch, epoch)
        subtree:add(f_sequence_number, seq_num)
        subtree:add(f_length, length)
        subtree:add(f_payload, buffer(offset+13, len))
        
        -- 获取内容类型的描述信息
        local content_type_val = content_type:uint()
        local content_type_str = ""
        if content_type_val == 20 then
            content_type_str = "Change Cipher Spec"
            -- 对于Change Cipher Spec类型，添加更详细的信息
            if len > 0 and buffer(offset+13, 1):uint() == 1 then
                content_type_str = content_type_str .. ": 1"
            end
        elseif content_type_val == 21 then
            content_type_str = "Alert"
            -- 对于Alert类型，添加更详细的信息
            if len >= 2 then
                local alert_level = buffer(offset+13, 1):uint()
                local alert_description = buffer(offset+14, 1):uint()
                local level_str = "Unknown"
                local desc_str = "Unknown"
                
                -- 警告级别
                if alert_level == 1 then
                    level_str = "Warning"
                elseif alert_level == 2 then
                    level_str = "Fatal"
                end
                
                -- 警告描述
                if alert_description == 0 then
                    desc_str = "Close Notify"
                elseif alert_description == 10 then
                    desc_str = "Unexpected Message"
                elseif alert_description == 20 then
                    desc_str = "Bad Record MAC"
                elseif alert_description == 21 then
                    desc_str = "Decryption Failed"
                elseif alert_description == 22 then
                    desc_str = "Record Overflow"
                elseif alert_description == 40 then
                    desc_str = "Handshake Failure"
                elseif alert_description == 42 then
                    desc_str = "Bad Certificate"
                elseif alert_description == 43 then
                    desc_str = "Unsupported Certificate"
                elseif alert_description == 44 then
                    desc_str = "Certificate Revoked"
                elseif alert_description == 45 then
                    desc_str = "Certificate Expired"
                elseif alert_description == 46 then
                    desc_str = "Certificate Unknown"
                elseif alert_description == 47 then
                    desc_str = "Illegal Parameter"
                elseif alert_description == 48 then
                    desc_str = "Unknown CA"
                elseif alert_description == 49 then
                    desc_str = "Access Denied"
                elseif alert_description == 50 then
                    desc_str = "Decode Error"
                elseif alert_description == 51 then
                    desc_str = "Decrypt Error"
                elseif alert_description == 70 then
                    desc_str = "Protocol Version"
                elseif alert_description == 71 then
                    desc_str = "Insufficient Security"
                elseif alert_description == 80 then
                    desc_str = "Internal Error"
                elseif alert_description == 90 then
                    desc_str = "User Canceled"
                elseif alert_description == 100 then
                    desc_str = "No Renegotiation"
                elseif alert_description == 110 then
                    desc_str = "Unsupported Extension"
                end
                
                content_type_str = content_type_str .. ": " .. level_str .. ", " .. desc_str
            end
        elseif content_type_val == 22 then
            content_type_str = "Handshake"
        elseif content_type_val == 23 then
            content_type_str = "Application Data"
            -- 对于应用数据，添加长度信息
            content_type_str = content_type_str .. " (" .. len .. " bytes)"
        elseif content_type_val == 255 then
            content_type_str = "Reserved"
        else
            content_type_str = "Unknown(" .. content_type_val .. ")"
        end
        
        -- 添加到info_items数组
        table.insert(info_items, content_type_str)

        -- 若为握手类型，则进一步解析握手结构
        if content_type:uint() == 22 and len >= 12 then
            local h_offset = offset + 13
            
            -- 检查是否有足够的数据来解析握手头部
            if h_offset + 12 > buffer:len() then
                subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Handshake header truncated")
                break
            end
            
            local h_type = buffer(h_offset, 1)
            local h_len = buffer(h_offset+1, 3)
            local h_seq = buffer(h_offset+4, 2)
            local h_frag_off = buffer(h_offset+6, 3)
            local h_frag_len = buffer(h_offset+9, 3)
            local h_body_len = h_len:uint()
            
            -- 处理分片
            local msg_type = h_type:uint()
            local msg_seq = h_seq:uint()
            local frag_offset = h_frag_off:uint()
            local frag_length = h_frag_len:uint()
            
            -- 检查是否为分片消息
            local is_fragment = (frag_length < h_body_len)
            
            -- 创建分片键
            local fragment_key = string.format("%d_%d", msg_type, msg_seq)
            
            -- 如果是分片，存储到分片表中
            if is_fragment then
                if not fragments[fragment_key] then
                    fragments[fragment_key] = {}
                end
                
                -- 存储分片信息
                -- 检查分片长度是否超出缓冲区范围
                local actual_frag_length = frag_length
                if h_offset+12+frag_length > buffer:len() then
                    actual_frag_length = buffer:len() - (h_offset+12)
                    -- 添加警告信息
                    subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Fragment length exceeds buffer size, truncating")
                end
                
                table.insert(fragments[fragment_key], {
                    offset = frag_offset,
                    length = actual_frag_length,
                    data = buffer(h_offset+12, actual_frag_length),
                    total_length = h_body_len
                })
            end

            -- 创建握手消息子树
            local message_info = "Handshake Message"
            if is_fragment then
                message_info = string.format("Handshake Message Fragment (offset=%d, length=%d)", frag_offset, frag_length)
            end
            
            -- 获取握手消息类型的描述信息
            local handshake_type_val = h_type:uint()
            local handshake_type_str = ""
            if handshake_type_val == 0 then
                handshake_type_str = "Hello Request"
            elseif handshake_type_val == 1 then
                handshake_type_str = "Client Hello"
            elseif handshake_type_val == 2 then
                handshake_type_str = "Server Hello"
            elseif handshake_type_val == 3 then
                handshake_type_str = "Hello Verify Request"
            elseif handshake_type_val == 11 then
                handshake_type_str = "Certificate"
            elseif handshake_type_val == 12 then
                handshake_type_str = "Server Key Exchange"
            elseif handshake_type_val == 13 then
                handshake_type_str = "Certificate Request"
            elseif handshake_type_val == 14 then
                handshake_type_str = "Server Hello Done"
            elseif handshake_type_val == 15 then
                handshake_type_str = "Certificate Verify"
            elseif handshake_type_val == 16 then
                handshake_type_str = "Client Key Exchange"
            elseif handshake_type_val == 20 then
                handshake_type_str = "Finished"
            elseif handshake_type_val == 255 then
                handshake_type_str = "Reserved"
            else
                handshake_type_str = "Unknown(" .. handshake_type_val .. ")"
            end
            
            -- 修改最后一个info_items中的握手消息信息
            local last_index = #info_items
            if is_fragment then
                info_items[last_index] = info_items[last_index] .. ": " .. handshake_type_str .. " (Fragment)"
            else
                info_items[last_index] = info_items[last_index] .. ": " .. handshake_type_str
            end
            local h_tree = subtree:add(dtlcp, buffer(h_offset, len), message_info)
            h_tree:add(f_handshake_type, h_type)
            h_tree:add(f_handshake_length, h_len)
            h_tree:add(f_handshake_seq, h_seq)
            h_tree:add(f_handshake_frag_offset, h_frag_off)
            h_tree:add(f_handshake_frag_length, h_frag_len)
            
            -- 尝试重组分片
            local body_buffer = nil
            local body_length = 0
            local use_reassembled = false
            
            -- 如果是分片消息，尝试重组
            if is_fragment then
                -- 检查是否所有分片都已收集
                local total_fragments = 0
                local collected_length = 0
                
                for _, fragment in ipairs(fragments[fragment_key]) do
                    total_fragments = total_fragments + 1
                    collected_length = collected_length + fragment.length
                end
                
                -- 如果收集到的长度等于总长度，尝试重组
                if collected_length == h_body_len then
                    local reassembled_data, reassembled_length = reassemble_fragments(msg_type, msg_seq, fragments[fragment_key])
                    
                    if reassembled_data then
                        -- 创建一个新的tvb来解析重组后的消息
                        body_buffer = ByteArray.tvb(reassembled_data, "Reassembled Handshake Message")
                        body_length = reassembled_length
                        use_reassembled = true
                        h_tree:add(f_handshake_body, body_buffer(0, body_length))
                        
                        -- 清除已重组的分片
                        fragments[fragment_key] = nil
                    end
                end
            end
            
            -- 如果没有使用重组数据，并且当前消息包含完整的消息体
            if not use_reassembled and len >= 12 + h_body_len then
                body_buffer = buffer
                body_length = h_body_len
                h_tree:add(f_handshake_body, buffer(h_offset+12, h_body_len))
                
                -- 解析ClientHello消息
                if h_type:uint() == 1 then
                    local ch_offset = h_offset + 12
                    local ch_version = buffer(ch_offset, 2)
                    local ch_random_time = buffer(ch_offset+2, 4)
                    local ch_random_bytes = buffer(ch_offset+6, 28)
                    local ch_session_id_len = buffer(ch_offset+34, 1)
                    local sid_len = ch_session_id_len:uint()
                    
                    local ch_tree = h_tree:add(dtlcp, buffer(ch_offset, 35 + sid_len), "ClientHello")
                    ch_tree:add(f_client_version, ch_version)
                    ch_tree:add(f_random_time, ch_random_time)
                    ch_tree:add(f_random_bytes, ch_random_bytes)
                    ch_tree:add(f_session_id_len, ch_session_id_len)
                    
                    if sid_len > 0 then
                        ch_tree:add(f_session_id, buffer(ch_offset+35, sid_len))
                    end
                    
                    -- 解析cookie
                    local cookie_len = buffer(ch_offset+35+sid_len, 1):uint()
                    ch_tree:add(f_cookie_len, buffer(ch_offset+35+sid_len, 1))
                    if cookie_len > 0 then
                        ch_tree:add(f_cookie, buffer(ch_offset+36+sid_len, cookie_len))
                    end
                    
                    -- 解析密码套件
                    local cipher_suites_len = buffer(ch_offset+36+sid_len+cookie_len, 2):uint()
                    ch_tree:add(f_cipher_suites_len, buffer(ch_offset+36+sid_len+cookie_len, 2))
                    
                    local cs_offset = ch_offset + 38 + sid_len + cookie_len
                    for i = 0, cipher_suites_len/2 - 1 do
                        ch_tree:add(f_cipher_suite, buffer(cs_offset + i*2, 2))
                    end
                    
                    -- 解析压缩方法
                    local comp_methods_len = buffer(cs_offset + cipher_suites_len, 1):uint()
                    ch_tree:add(f_compression_methods_len, buffer(cs_offset + cipher_suites_len, 1))
                    
                    local cm_offset = cs_offset + cipher_suites_len + 1
                    for i = 0, comp_methods_len - 1 do
                        ch_tree:add(f_compression_method, buffer(cm_offset + i, 1))
                    end
                -- 解析ServerHello消息
                elseif h_type:uint() == 2 then
                    local sh_offset = h_offset + 12
                    local sh_version = buffer(sh_offset, 2)
                    local sh_random = buffer(sh_offset+2, 32)
                    local sh_session_id_len = buffer(sh_offset+34, 1)
                    local sid_len = sh_session_id_len:uint()
                    
                    local sh_tree = h_tree:add(dtlcp, buffer(sh_offset, 35 + sid_len), "ServerHello")
                    sh_tree:add(f_server_version, sh_version)
                    sh_tree:add(f_server_random, sh_random)
                    sh_tree:add(f_server_session_id_len, sh_session_id_len)
                    
                    if sid_len > 0 then
                        sh_tree:add(f_server_session_id, buffer(sh_offset+35, sid_len))
                    end
                    
                    -- 解析密码套件
                    sh_tree:add(f_server_cipher_suite, buffer(sh_offset+35+sid_len, 2))
                    
                    -- 解析压缩方法
                    sh_tree:add(f_server_compression_method, buffer(sh_offset+37+sid_len, 1))
                -- 解析Certificate消息
                elseif h_type:uint() == 11 then
                    local cert_offset = h_offset + 12
                    local cert_length = buffer(cert_offset, 3)
                    local cert_len = cert_length:uint()
                    
                    local cert_tree = h_tree:add(dtlcp, buffer(cert_offset, 3 + cert_len), "Certificate")
                    cert_tree:add(f_certificate_length, cert_length)
                    
                    -- 检查选择的密码套件类型
                    -- 这里需要根据实际情况判断是标准证书结构还是IBC结构
                    -- 由于无法直接获取之前的密码套件信息，这里简化处理
                    -- 实际应用中可能需要保存之前的密码套件信息
                    
                    -- 尝试解析为IBC结构
                    if cert_len >= 2 then -- 至少需要2字节的IBC ID长度
                        local ibc_id_length = buffer(cert_offset+3, 2)
                        local ibc_id_len = ibc_id_length:uint()
                        
                        -- 如果长度合理，假设为IBC结构
                        if ibc_id_len > 0 and ibc_id_len < cert_len - 2 then
                            cert_tree:add(f_ibc_id_length, ibc_id_length)
                            cert_tree:add(f_ibc_id, buffer(cert_offset+5, ibc_id_len))
                            
                            -- IBC参数长度为剩余的数据
                            local param_len = cert_len - 2 - ibc_id_len
                            if param_len > 0 then
                                cert_tree:add(f_ibc_parameter, buffer(cert_offset+5+ibc_id_len, param_len))
                            end
                        else
                            -- 否则作为标准证书结构处理
                            cert_tree:add(f_certificate_data, buffer(cert_offset+3, cert_len))
                        end
                    else
                        -- 数据不足，作为标准证书结构处理
                        if cert_len > 0 then
                            cert_tree:add(f_certificate_data, buffer(cert_offset+3, cert_len))
                        end
                    end
                -- 解析ServerKey Exchange消息
                elseif h_type:uint() == 12 then
                    local ske_offset = h_offset + 12
                    local ske_tree = h_tree:add(dtlcp, buffer(ske_offset, h_body_len), "Server Key Exchange")
                    
                    -- 解析密钥交换算法类型
                    -- 注意：实际协议中可能没有显式的算法类型字段，这里为了解析方便添加
                    -- 实际应用中可能需要根据之前的密码套件信息来判断
                    local key_exchange_alg = buffer(ske_offset, 1):uint()
                    ske_tree:add(f_key_exchange_algorithm, buffer(ske_offset, 1))
                    
                    local params_offset = ske_offset + 1
                    
                    -- 根据不同的密钥交换算法解析不同的结构
                    if key_exchange_alg == 1 then -- ECDHE
                        -- 解析ECDHE参数
                        local params_len = 32 -- 假设参数长度为32字节
                        ske_tree:add(f_ecdhe_params, buffer(params_offset, params_len))
                        
                        -- 解析公钥
                        local public_key_len = 65 -- 假设公钥长度为65字节
                        ske_tree:add(f_ecdhe_public, buffer(params_offset + params_len, public_key_len))
                        
                        -- 解析签名参数
                        local signed_offset = params_offset + params_len + public_key_len
                        ske_tree:add(f_client_random, buffer(signed_offset, 32))
                        ske_tree:add(f_ske_server_random, buffer(signed_offset + 32, 32))
                        
                        -- 剩余部分为签名
                        local sig_len = h_body_len - (signed_offset - ske_offset + 64)
                        if sig_len > 0 then
                            ske_tree:add(f_signed_params, buffer(signed_offset + 64, sig_len))
                        end
                    elseif key_exchange_alg == 2 then -- ECC
                        -- 解析签名参数
                        ske_tree:add(f_client_random, buffer(params_offset, 32))
                        ske_tree:add(f_ske_server_random, buffer(params_offset + 32, 32))
                        
                        -- 解析ASN.1证书
                        local cert_len_offset = params_offset + 64
                        local cert_len = buffer(cert_len_offset, 2):uint()
                        ske_tree:add(f_asn1_cert, buffer(cert_len_offset + 2, cert_len))
                        
                        -- 剩余部分为签名
                        local sig_offset = cert_len_offset + 2 + cert_len
                        local sig_len = h_body_len - (sig_offset - ske_offset)
                        if sig_len > 0 then
                            ske_tree:add(f_signed_params, buffer(sig_offset, sig_len))
                        end
                    elseif key_exchange_alg == 3 then -- IBSDH
                        -- 解析IBSDH参数
                        local params_len = 64 -- 假设参数长度为64字节
                        ske_tree:add(f_ibsdh_params, buffer(params_offset, params_len))
                        
                        -- 解析签名参数
                        local signed_offset = params_offset + params_len
                        ske_tree:add(f_client_random, buffer(signed_offset, 32))
                        ske_tree:add(f_ske_server_random, buffer(signed_offset + 32, 32))
                        
                        -- 剩余部分为签名
                        local sig_len = h_body_len - (signed_offset - ske_offset + 64)
                        if sig_len > 0 then
                            ske_tree:add(f_signed_params, buffer(signed_offset + 64, sig_len))
                        end
                    elseif key_exchange_alg == 4 then -- IBC
                        -- 解析IBC参数
                        local params_len = 64 -- 假设参数长度为64字节
                        ske_tree:add(f_ibc_params, buffer(params_offset, params_len))
                        
                        -- 解析加密公钥
                        local enc_key_len = 1024 -- 加密公钥长度为1024字节
                        ske_tree:add(f_ibc_encryption_key, buffer(params_offset + params_len, enc_key_len))
                        
                        -- 解析签名参数
                        local signed_offset = params_offset + params_len + enc_key_len
                        ske_tree:add(f_client_random, buffer(signed_offset, 32))
                        ske_tree:add(f_ske_server_random, buffer(signed_offset + 32, 32))
                        
                        -- 剩余部分为签名
                        local sig_len = h_body_len - (signed_offset - ske_offset + 64)
                        if sig_len > 0 then
                            ske_tree:add(f_signed_params, buffer(signed_offset + 64, sig_len))
                        end
                    elseif key_exchange_alg == 5 then -- RSA
                        -- 解析签名参数
                        ske_tree:add(f_client_random, buffer(params_offset, 32))
                        ske_tree:add(f_ske_server_random, buffer(params_offset + 32, 32))
                        
                        -- 解析ASN.1证书
                        local cert_len_offset = params_offset + 64
                        local cert_len = buffer(cert_len_offset, 2):uint()
                        ske_tree:add(f_asn1_cert, buffer(cert_len_offset + 2, cert_len))
                        
                        -- 剩余部分为签名
                        local sig_offset = cert_len_offset + 2 + cert_len
                        local sig_len = h_body_len - (sig_offset - ske_offset)
                        if sig_len > 0 then
                            ske_tree:add(f_signed_params, buffer(sig_offset, sig_len))
                        end
                    else
                        -- 未知的密钥交换算法，将剩余数据作为原始数据显示
                        ske_tree:add(f_signed_params, buffer(params_offset, h_body_len - 1))
                    end
                    
                -- 解析Certificate Request消息
                elseif h_type:uint() == 13 then
                    local cr_offset = h_offset + 12
                    local cr_tree = h_tree:add(dtlcp, buffer(cr_offset, h_body_len), "Certificate Request")
                    
                    -- 解析证书类型列表
                    local cert_types_length = buffer(cr_offset, 1):uint()
                    cr_tree:add(f_cert_types_length, buffer(cr_offset, 1))
                    
                    local ct_offset = cr_offset + 1
                    for i = 0, cert_types_length - 1 do
                        cr_tree:add(f_cert_type, buffer(ct_offset + i, 1))
                    end
                    
                    -- 解析证书颁发机构列表
                    local ca_offset = ct_offset + cert_types_length
                    local cert_authorities_length = buffer(ca_offset, 2):uint()
                    cr_tree:add(f_cert_authorities_length, buffer(ca_offset, 2))
                    
                    -- 解析每个证书颁发机构
                    local dn_offset = ca_offset + 2
                    local remaining_length = cert_authorities_length
                    
                    while remaining_length > 0 do
                        local dn_length = buffer(dn_offset, 1):uint()
                        cr_tree:add(f_cert_authority_length, buffer(dn_offset, 1))
                        
                        if dn_length > 0 then
                            cr_tree:add(f_cert_authority, buffer(dn_offset + 1, dn_length))
                        end
                        
                        dn_offset = dn_offset + 1 + dn_length
                        remaining_length = remaining_length - (1 + dn_length)
                    end
                    
                -- 解析Client Key Exchange消息
                elseif h_type:uint() == 16 then
                    local cke_offset = h_offset + 12
                    local cke_tree = h_tree:add(dtlcp, buffer(cke_offset, h_body_len), "Client Key Exchange")
                    
                    -- 解析密钥交换算法类型
                    -- 注意：实际协议中可能没有显式的算法类型字段，这里为了解析方便添加
                    -- 实际应用中可能需要根据之前的密码套件信息来判断
                    local key_exchange_alg = buffer(cke_offset, 1):uint()
                    cke_tree:add(f_client_key_exchange_algorithm, buffer(cke_offset, 1))
                    
                    local params_offset = cke_offset + 1
                    
                    -- 根据不同的密钥交换算法解析不同的结构
                    if key_exchange_alg == 1 then -- ECDHE
                        -- 解析ECDHE参数长度
                        local params_len_bytes = buffer(params_offset, 2)
                        local params_len = params_len_bytes:uint()
                        
                        -- 解析ECDHE参数
                        if params_len > 0 then
                            -- 假设参数包含曲线参数和公钥
                            local curve_params_len = 32 -- 假设曲线参数长度为32字节
                            cke_tree:add(f_client_ecdhe_params, buffer(params_offset + 2, curve_params_len))
                            
                            -- 解析公钥
                            local public_key_len = params_len - curve_params_len
                            if public_key_len > 0 then
                                cke_tree:add(f_client_ecdhe_public, buffer(params_offset + 2 + curve_params_len, public_key_len))
                            end
                        end
                    elseif key_exchange_alg == 2 then -- ECC
                        -- 解析ECC加密的预主密钥长度
                        local pms_len_bytes = buffer(params_offset, 2)
                        local pms_len = pms_len_bytes:uint()
                        
                        -- 解析ECC加密的预主密钥
                        if pms_len > 0 then
                            cke_tree:add(f_ecc_encrypted_pms, buffer(params_offset + 2, pms_len))
                        end
                    elseif key_exchange_alg == 3 then -- IBSDH
                        -- 解析IBSDH参数长度
                        local params_len_bytes = buffer(params_offset, 2)
                        local params_len = params_len_bytes:uint()
                        
                        -- 解析IBSDH参数
                        if params_len > 0 then
                            cke_tree:add(f_client_ibsdh_params, buffer(params_offset + 2, params_len))
                        end
                    elseif key_exchange_alg == 4 then -- IBC
                        -- 解析IBC加密的预主密钥长度
                        local pms_len_bytes = buffer(params_offset, 2)
                        local pms_len = pms_len_bytes:uint()
                        
                        -- 解析IBC加密的预主密钥
                        if pms_len > 0 then
                            cke_tree:add(f_ibc_encrypted_pms, buffer(params_offset + 2, pms_len))
                        end
                    elseif key_exchange_alg == 5 then -- RSA
                        -- 解析RSA加密的预主密钥长度
                        local pms_len_bytes = buffer(params_offset, 2)
                        local pms_len = pms_len_bytes:uint()
                        
                        -- 解析RSA加密的预主密钥
                        if pms_len > 0 then
                            cke_tree:add(f_rsa_encrypted_pms, buffer(params_offset + 2, pms_len))
                            
                            -- 注意：实际上加密的预主密钥无法直接解析其内部结构
                            -- 以下代码仅作为示例，实际应用中可能无法直接看到预主密钥的明文结构
                            -- cke_tree:add(f_pms_client_version, buffer(params_offset + 2, 2))
                            -- cke_tree:add(f_pms_random, buffer(params_offset + 4, 46))
                        end
                    else
                        -- 未知的密钥交换算法，将剩余数据作为原始数据显示
                        cke_tree:add(f_handshake_body, buffer(params_offset, h_body_len - 1))
                    end
                    
                -- 解析CertificateVerify消息
                elseif h_type:uint() == 15 then
                    local cv_offset = h_offset + 12
                    local cv_tree = h_tree:add(dtlcp, buffer(cv_offset, h_body_len), "Certificate Verify")
                    
                    -- 确定使用哪个缓冲区
                    local buf = use_reassembled and body_buffer or buffer
                    local buf_offset = use_reassembled and 0 or cv_offset
                    
                    -- 解析签名算法
                    local sig_alg = buf(buf_offset, 1):uint()
                    cv_tree:add(f_signature_algorithm, buf(buf_offset, 1))
                    
                    local sig_offset = buf_offset + 1
                    
                    -- 根据不同的签名算法解析不同的结构
                    if sig_alg == 1 then -- rsa_sha256
                        -- 解析SHA256哈希值
                        cv_tree:add(f_signature_hash_sha256, buf(sig_offset, 20))
                        
                        -- 解析签名数据
                        local sig_data_offset = sig_offset + 20
                        local sig_data_len = body_length - (use_reassembled and 21 or (sig_data_offset - cv_offset))
                        if sig_data_len > 0 then
                            cv_tree:add(f_signature_data, buf(sig_data_offset, sig_data_len))
                        end
                        
                        -- 添加注释说明哈希计算
                        cv_tree:add(dtlcp, nil, "Note: SHA256 hash is calculated over all handshake messages from ClientHello to this message (excluding header)")
                    elseif sig_alg == 2 then -- rsa_sm3
                        -- 解析SM3哈希值
                        cv_tree:add(f_signature_hash_sm3, buf(sig_offset, 32))
                        
                        -- 解析签名数据
                        local sig_data_offset = sig_offset + 32
                        local sig_data_len = body_length - (use_reassembled and 33 or (sig_data_offset - cv_offset))
                        if sig_data_len > 0 then
                            cv_tree:add(f_signature_data, buf(sig_data_offset, sig_data_len))
                        end
                        
                        -- 添加注释说明哈希计算
                        cv_tree:add(dtlcp, nil, "Note: SM3 hash is calculated over all handshake messages from ClientHello to this message (excluding header)")
                    elseif sig_alg == 3 then -- ecc_sm3
                        -- 解析SM3哈希值
                        cv_tree:add(f_signature_hash_sm3, buf(sig_offset, 32))
                        
                        -- 解析签名数据
                        local sig_data_offset = sig_offset + 32
                        local sig_data_len = body_length - (use_reassembled and 33 or (sig_data_offset - cv_offset))
                        if sig_data_len > 0 then
                            cv_tree:add(f_signature_data, buf(sig_data_offset, sig_data_len))
                        end
                        
                        -- 添加注释说明哈希计算
                        cv_tree:add(dtlcp, nil, "Note: SM3 hash is calculated over all handshake messages from ClientHello to this message (excluding header)")
                    elseif sig_alg == 4 then -- ibs_sm3
                        -- 解析SM3哈希值
                        cv_tree:add(f_signature_hash_sm3, buf(sig_offset, 32))
                        
                        -- 解析签名数据
                        local sig_data_offset = sig_offset + 32
                        local sig_data_len = body_length - (use_reassembled and 33 or (sig_data_offset - cv_offset))
                        if sig_data_len > 0 then
                            cv_tree:add(f_signature_data, buf(sig_data_offset, sig_data_len))
                        end
                        
                        -- 添加注释说明哈希计算
                        cv_tree:add(dtlcp, nil, "Note: SM3 hash is calculated over all handshake messages from ClientHello to this message (excluding header)")
                    else
                        -- 未知的签名算法，将剩余数据作为原始数据显示
                        cv_tree:add(f_handshake_body, buf(sig_offset, body_length - 1))
                    end
                    
                -- 解析Finished消息
                elseif h_type:uint() == 20 then
                    local fin_offset = h_offset + 12
                    local fin_tree = h_tree:add(dtlcp, buffer(fin_offset, h_body_len), "Finished")
                    
                    -- 确定使用哪个缓冲区
                    local buf = use_reassembled and body_buffer or buffer
                    local buf_offset = use_reassembled and 0 or fin_offset
                    
                    -- Finished消息包含12字节的verify_data
                    -- verify_data是通过PRF(master_secret, finished_label, SM3(handshake_messages))[0..11]生成的
                    -- 对于客户端发送的消息，finished_label是"clientfinished"
                    -- 对于服务端发送的消息，finished_label是"serverfinished"
                    if body_length >= 12 then
                        fin_tree:add(f_verify_data, buf(buf_offset, 12))
                        
                        -- 添加注释说明这是客户端还是服务端的Finished消息
                        -- 注意：这里简化处理，实际应用中可能需要根据之前的消息流向判断
                        local direction = "Unknown"
                        if pinfo.src_port == 60040 then
                            direction = "Server"
                        else
                            direction = "Client"
                        end
                        fin_tree:add(dtlcp, nil, string.format("%s Finished Message (verify_data generated with '%sfinished' label)", direction, string.lower(direction)))
                        
                        -- 添加注释说明哈希计算
                        fin_tree:add(dtlcp, nil, "Note: Verify data is calculated using PRF(master_secret, finished_label, SM3(handshake_messages))[0..11]")
                        fin_tree:add(dtlcp, nil, "      where handshake_messages includes all messages from ClientHello to this message (excluding header)")
                        
                        -- 如果是分片消息，添加重组信息
                        if is_fragment then
                            fin_tree:add(dtlcp, nil, "Note: This message was reassembled from multiple fragments")
                        end
                    else
                        fin_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Finished message too short")
                    end
                    
                -- 解析Server Hello Done消息
                elseif h_type:uint() == 14 then
                    -- Server Hello Done是一个空结构体，不包含任何数据
                    -- 只需要添加一个标签即可
                    local shd_offset = h_offset + 12
                    h_tree:add(dtlcp, buffer(shd_offset, 0), "Server Hello Done")
                    -- 注意：这里传入长度为0，因为Server Hello Done消息没有内容
                end
            else
                h_tree:add_expert_info(PI_MALFORMED, PI_WARN, "Handshake body truncated")
            end
        end

        offset = offset + 13 + len
    end
    
    -- 设置info列信息
    if #info_items > 0 then
        pinfo.cols.info = table.concat(info_items, ", ")
    end
end

-- DTLCP协议启发式检测函数
local function heuristic_dtlcp(buffer, pinfo, tree)
    -- 检查数据包长度是否至少为DTLCP头部长度(13字节)
    if buffer:len() < 13 then return false end
    
    -- 安全地获取字段值，避免越界访问
    local content_type, version, length
    
    -- 使用pcall捕获可能的异常
    local status, err = pcall(function()
        content_type = buffer(0,1):uint()
        version = buffer(1,2):uint()
        length = buffer(11,2):uint()
    end)
    
    -- 如果捕获到异常，说明缓冲区访问出错
    if not status then return false end
    
    -- 检查内容类型是否为有效的DTLCP类型 (20-23, 255)
    if not (content_type >= 20 and content_type <= 23 or content_type == 255) then return false end
    
    -- 检查版本号是否合理 (DTLCP版本通常为0x0100-0x0305范围)
    if not (version >= 0x0100 and version <= 0x0305) then return false end
    
    -- 检查长度字段是否合理
    if length > buffer:len() - 13 then return false end
    
    -- 对握手消息类型进行额外检查
    if content_type == 22 and buffer:len() >= 14 then
        -- 安全地获取握手类型
        local handshake_type
        status, err = pcall(function()
            handshake_type = buffer(13,1):uint()
        end)
        
        -- 如果捕获到异常或握手类型无效，返回false
        if not status or handshake_type > 20 then return false end
    end
    
    -- 如果是握手消息，进一步检查握手类型
    if content_type == 22 and buffer:len() >= 14 then
        local handshake_type = buffer(13,1):uint()
        -- 检查握手类型是否为有效值 (0-3, 11-16, 20, 255)
        if not (handshake_type <= 3 or 
                (handshake_type >= 11 and handshake_type <= 16) or 
                handshake_type == 20 or 
                handshake_type == 255) then
            return false
        end
    end
    
    -- 通过所有检查，认为是DTLCP协议
    dtlcp.dissector(buffer, pinfo, tree)
    return true
end

-- 将协议绑定到特定UDP端口
--local udp_port = DissectorTable.get("udp.port")
--udp_port:add(60040, dtlcp)

-- 注册启发式解析器，使其能够自动识别所有UDP流量中的DTLCP协议
dtlcp:register_heuristic("udp", heuristic_dtlcp)