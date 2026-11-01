"""Scope definition and target validation routes."""

import ipaddress

from fastapi import APIRouter, Depends, HTTPException, status

from reconforge.api.dependencies import verify_api_key
from reconforge.api.models import ScopeValidationRequest, ScopeValidationResponse
from reconforge.core.exceptions import ScopeViolationError
from reconforge.core.models import TargetScope
from reconforge.core.scope import ScopeManager
from reconforge.utils.network import parse_ports

router = APIRouter(
    prefix="/scope", tags=["Scope Validation"], dependencies=[Depends(verify_api_key)]
)


@router.post(
    "/validate",
    response_model=ScopeValidationResponse,
    summary="Validate scanning scope boundaries",
)
async def validate_scope(req: ScopeValidationRequest) -> ScopeValidationResponse:
    """Validate target ranges and port specifications against authorization constraints."""
    try:
        parsed_ports = parse_ports(req.ports)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid port specification: {err}",
        ) from err

    try:
        scope = TargetScope(
            allowed_targets=req.targets,
            allowed_ports=req.ports,
            excluded_targets=req.excluded_targets,
            allow_public_targets=req.allow_public,
            lab_mode=True,
        )
        manager = ScopeManager(scope)
        first_port = parsed_ports[0]
        for t in req.targets:
            t_clean = t.strip()
            try:
                ip_val = ipaddress.ip_address(t_clean)
                manager.validate_target_and_port(ip_val, first_port)
            except ValueError:
                if "/" in t_clean:
                    try:
                        net = ipaddress.ip_network(t_clean, strict=False)
                        manager.validate_target_and_port(net.network_address, first_port)
                    except ValueError:
                        pass

        targets = manager.expand_static_targets()
        warnings: list[str] = []

        if len(targets) > 512:
            warnings.append(
                f"Scope contains {len(targets)} targets. Consider reducing concurrency or rate limits."
            )

        return ScopeValidationResponse(
            valid=True,
            total_targets=len(targets),
            allowed_targets=req.targets,
            allowed_ports_count=len(parsed_ports),
            warnings=warnings,
            error=None,
        )
    except ScopeViolationError as err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Scope authorization violation: {err}",
        ) from err
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scope configuration error: {err}",
        ) from err
