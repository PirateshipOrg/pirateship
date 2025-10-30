function apply(phdr) {
    if (!phdr.cwt.iss) {
        return 'Issuer not set';
    } else if (!phdr.cwt.iss.startsWith('did:x509:0:sha256:')) {
        return 'Invalid issuer';
    } 
    return true;
}
