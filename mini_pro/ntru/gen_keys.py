from NTRUdecrypt import NTRUdecrypt

# Cloud Key Generation
cloud = NTRUdecrypt()
print("Generating keys for Cloud...")
cloud.setNpq(N=503, p=3, q=256)
cloud.genfg()  # generate f, g and test invertibility
cloud.genh()   # generate public key
cloud.writePub("cloud")
cloud.writePriv("cloud")
print(" Cloud keys saved as 'cloud.pub' and 'cloud.priv'")

# Fog Key Generation
fog = NTRUdecrypt()
print("Generating keys for Fog...")
fog.setNpq(N=503, p=3, q=256)
fog.genfg()
fog.genh()
fog.writePub("fog")
fog.writePriv("fog")
print(" Fog keys saved as 'fog.pub' and 'fog.priv'")

edge = NTRUdecrypt()
print("Generating keys for Edge...")
edge.setNpq(N=503, p=3, q=256)
edge.genfg()
edge.genh()
edge.writePub("edge")
edge.writePriv("edge")
print(" Edge keys saved as 'edge.pub' and 'edge.priv'")

