from abc import ABC, abstractmethod
from typing import List, Dict, Any

class Tool(ABC):
    """
    Classe base astratta per tutti i tool del modulo ASM.
    Tutti i tool specifici (es. NmapTool) devono ereditare da questa classe
    e implementare i metodi astratti `run` e `get_results`.
    """

    def __init__(self):
        """
        Inizializza il tool.
        Crea un dizionario vuoto `self.results` per memorizzare i risultati delle scansioni.
        """
        self.results = {}

    @abstractmethod
    def run(self, domains: List[str], params: Dict[str, Any]) -> None:
        """
        Esegue il tool sui domini specificati utilizzando i parametri forniti.
        Questo metodo deve essere implementato dalle sottoclassi.

        Args:
            domains (List[str]): Una lista di domini o indirizzi IP da scansionare.
            params (Dict[str, Any]): Un dizionario contenente i parametri di configurazione
            per la scansione (es. tipo di scansione, porte, timeout).
        """
        pass

    @abstractmethod
    def get_results(self) -> str:
        """
        Restituisce i risultati della scansione formattati come stringa JSON.
        Questo metodo deve essere implementato dalle sottoclassi.

        Returns:
            str: Una stringa contenente i risultati in formato JSON.
        """
        pass
