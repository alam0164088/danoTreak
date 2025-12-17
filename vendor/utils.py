# vendor/utils.py
from .models import Redemption
from django.db import transaction


def generate_aliffited_id():
    """
    Generate a unique ALFF-prefixed id in a small critical section.

    We select the last Redemption row that already has an aliffited_id
    and lock it with select_for_update() inside a transaction so concurrent
    generators serialize and produce unique incrementing ids.

    Note: this is lightweight and avoids adding a separate counter table.
    """
    with transaction.atomic():
        last = (
            Redemption.objects.select_for_update()
            .filter(aliffited_id__isnull=False)
            .order_by('-id')
            .first()
        )
        if last and last.aliffited_id:
            try:
                num = int(last.aliffited_id.replace('ALFF', '')) + 1
            except ValueError:
                num = 1
        else:
            num = 1
        return f"ALFF{num:05d}"
    



