"""entry points: 所有 handler 的汇合处"""
from __future__ import annotations
import src.svc_00 as svc_00
import src.svc_01 as svc_01
import src.svc_02 as svc_02
import src.svc_03 as svc_03
import src.svc_04 as svc_04
import src.svc_05 as svc_05
import src.svc_06 as svc_06


def dispatch(request):
    """HTTP 请求入口：参数直接来自外部，未做任何校验。"""
    if request.get('load_00') is not None:
        return svc_00.load_00(request['load_00'])
    if request.get('safe_load_01') is not None:
        return svc_00.safe_load_01(request['safe_load_01'])
    if request.get('safe_load_02') is not None:
        return svc_01.safe_load_02(request['safe_load_02'])
    if request.get('safe_load_03') is not None:
        return svc_01.safe_load_03(request['safe_load_03'])
    if request.get('load_04') is not None:
        return svc_02.load_04(request['load_04'])
    if request.get('safe_load_05') is not None:
        return svc_02.safe_load_05(request['safe_load_05'])
    if request.get('load_06') is not None:
        return svc_03.load_06(request['load_06'])
    if request.get('safe_load_07') is not None:
        return svc_03.safe_load_07(request['safe_load_07'])
    if request.get('load_08') is not None:
        return svc_04.load_08(request['load_08'])
    if request.get('load_09') is not None:
        return svc_04.load_09(request['load_09'])
    if request.get('load_10') is not None:
        return svc_05.load_10(request['load_10'])
    if request.get('load_11') is not None:
        return svc_05.load_11(request['load_11'])
    if request.get('safe_load_12') is not None:
        return svc_06.safe_load_12(request['safe_load_12'])
    if request.get('load_13') is not None:
        return svc_06.load_13(request['load_13'])
    return None
