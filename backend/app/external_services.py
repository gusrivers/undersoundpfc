import httpx
from fastapi import HTTPException, status
from app.logger import logger

async def buscar_artista_musicbrainz(nome_artista: str) -> dict:
    url = f"https://musicbrainz.org/ws/2/artist/?query=artist:{nome_artista}&fmt=json"
    headers = {"User-Agent": "UndersoundPFC/1.0.0 ( contato@undersound.com.br )"}
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=5.0)
            if response.status_code == 200:
                data = response.json()
                artistas = data.get("artists", [])
                if artistas:
                    primeiro = artistas[0]
                    return {
                        "nome": primeiro.get("name"),
                        "pais": primeiro.get("country", "Desconhecido"),
                        "tipo": primeiro.get("type", "Banda/Solo"),
                        "disambiguation": primeiro.get("disambiguation", "")
                    }
            
            # FALLBACK DE SEGURANÇA
            logger.warning(f"MusicBrainz retornou status {response.status_code}. Utilizando dados simulados de contingência.")
            return {
                "nome": nome_artista.capitalize(),
                "pais": "BR (Simulado)",
                "tipo": "Banda Underground",
                "disambiguation": "Dados recuperados via contingência local para demonstração acadêmica."
            }

    except Exception as e:
        logger.error(f"Erro ao consultar API Externa do MusicBrainz: {str(e)}")
        return {
            "nome": nome_artista.capitalize(),
            "pais": "BR (Fallback)",
            "tipo": "Banda Independente",
            "disambiguation": "Registro alternativo por indisponibilidade temporária da API externa."
        }