import httpx
from fastapi import HTTPException, status
from app.logger import logger

async def buscar_artista_musicbrainz(nome_artista: str) -> dict:
    """Consome a API externa pública do MusicBrainz para consultar dados de artistas[cite: 1, 3]"""
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
            return {"mensagem": "Nenhum artista encontrado na base externa do MusicBrainz."}
    except Exception as e:
        logger.error(f"Erro ao consultar API Externa do MusicBrainz: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Serviço externo de consulta musical temporariamente indisponível."
        )