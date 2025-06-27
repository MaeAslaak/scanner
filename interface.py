import streamlit as st
import scanner

st.set_page_config(page_title="Scanner de vulnérabilités", layout="centered")

st.title("🔍 Scanner de vulnérabilités réseau")
st.write("Entrez une adresse IP ou une plage (ex : 192.168.1.0/24) pour lancer le scan.")

cible = st.text_input("Adresse IP / Plage réseau", "192.168.1.0/24")

if st.button("Lancer le scan"):
    with st.spinner("Scan en cours..."):
        resultat = scanner.scan_reseau(cible)
        scanner.exporter_resultats_csv(resultat)
        vuln = scanner.detecter_vulnerabilites(resultat)

    st.success("✅ Scan terminé !")
    st.write("📤 Résultats exportés dans `resultats_scan.csv`")

    if vuln:
        st.subheader("⚠️ Ports vulnérables détectés")
        st.table(vuln)
    else:
        st.info("Aucune vulnérabilité détectée.")
