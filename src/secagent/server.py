from dotenv import load_dotenv
from mcp.server.mcpserver import MCPServer

from secagent.tools import nvd

load_dotenv()

mcp = MCPServer("secagent")


@mcp.tool()
async def lookup_cve(cve_id: str) -> dict:
    """Look up a known vulnerability by its CVE id (for example CVE-2021-44228).

    Use this when the user mentions a CVE id or asks how severe a specific vulnerability is.
    Returns the description, CVSS score and severity, CWE weakness types, publication date
    and up to 5 reference links. Returns an 'error' field if the id is invalid or not found.
    """
    return await nvd.lookup_cve(cve_id)


def main():
    mcp.run()


if __name__ == "__main__":
    main()