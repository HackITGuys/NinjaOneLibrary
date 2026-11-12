"""Organisations and their locations."""

from __future__ import annotations

from NinjaOne.client import NinjaOneClient
from NinjaOne.models import Location, Organization


def list_organizations(client: NinjaOneClient) -> list[Organization]:
    """Every organisation (brief records: id, name, description, approval mode)."""
    return [Organization.model_validate(raw) for raw in client.paginate_after("/organizations")]


def get_organization(client: NinjaOneClient, organization_id: int) -> Organization:
    """One organisation, detailed: includes its locations."""
    organization = Organization.model_validate(client.get_object(f"/organization/{organization_id}"))
    for location in organization.locations or []:
        location.organization_id = organization.id
    return organization


def find_organizations(
    client: NinjaOneClient,
    query: int | str,
    organizations: list[Organization] | None = None,
) -> list[Organization]:
    """Organisations matching an id or a name.

    An int (or an all-digit string) matches the id. Otherwise an exact, case-insensitive
    name match wins; failing that, every organisation whose name contains `query`.
    Pass `organizations` to search an already-fetched list instead of calling the API.
    """
    candidates = organizations if organizations is not None else list_organizations(client)
    text = str(query).strip()
    if isinstance(query, int) or text.isdigit():
        return [org for org in candidates if org.id == int(text)]
    needle = text.lower()
    exact = [org for org in candidates if org.name.lower() == needle]
    if exact:
        return exact
    return [org for org in candidates if needle in org.name.lower()]


def list_locations(client: NinjaOneClient, organization_id: int | None = None) -> list[Location]:
    """Every location, or one organisation's locations."""
    if organization_id is None:
        return [Location.model_validate(raw) for raw in client.paginate_after("/locations")]
    locations = [
        Location.model_validate(raw) for raw in client.get_list(f"/organization/{organization_id}/locations")
    ]
    for location in locations:
        location.organization_id = organization_id
    return locations
