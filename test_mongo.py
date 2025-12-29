from pymongo import MongoClient

# Ganti <passwordmu> dengan password MongoDB Atlas kamu
client = MongoClient("mongodb+srv://hareemahwal383_db_user:ptYJPM6qIMhHMSwH@cluster0.jamdlfe.mongodb.net/?appName=Cluster0")

# Pilih database, bisa diganti nama lain
db = client.test  

# Test koneksi
try:
    collections = db.list_collection_names()
    print("Koneksi berhasil!")
    print("Daftar collection:", collections)
except Exception as e:
    print("Terjadi error saat koneksi:", e)

# ----------------------------
# Tambahkan kode insert data contoh
murid_collection = db.murid

# Insert data contoh
murid_collection.insert_one({
    "nama": "Budi",
    "kelas": "5A",
    "tipe_karakter": "Analitis"
})

# Cek daftar collection lagi setelah insert
print("Daftar collection setelah insert:", db.list_collection_names())