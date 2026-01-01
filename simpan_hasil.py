# simpan_hasil.py
from db import get_collection
from datetime import datetime

def simpan_hasil(
    nama_siswa,
    kelas,
    data_input,
    hasil_prediksi
):
    """
    Simpan hasil klasifikasi ke MongoDB
    Collection: hasil
    """

    collection = get_collection("hasil")

    dokumen = {
        "nama_siswa": nama_siswa,
        "kelas": kelas,
        "input": data_input,
        "label": hasil_prediksi.get("label"),
        "probabilities": hasil_prediksi.get("probabilities"),
        "explanation": hasil_prediksi.get("explanation"),
        "tips": hasil_prediksi.get("tips"),
        "created_at": datetime.utcnow()
    }

    collection.insert_one(dokumen)

    print(f"✅ Data {nama_siswa} berhasil disimpan ke MongoDB (collection: hasil)")
