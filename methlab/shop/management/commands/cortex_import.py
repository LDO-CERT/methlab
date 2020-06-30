import sys
import cortex4py
from methlab.shop.models import InternalInfo, Analyzer
from cortex4py.api import Api
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Sync Cortex Analyzers"

    def handle(self, *args, **kwargs):

        analyzers = Analyzer.objects.all()
        analyzers_name = [x.name for x in analyzers]
        if len(analyzers) > 0:
            self.stdout.write(
                self.style.SUCCESS("Analyzers: {}".format(", ".join(analyzers_name)))
            )
        else:
            self.stdout.write(self.style.SUCCESS("No analyzers in db"))

        info = InternalInfo.objects.first()
        if info.http_proxy and info.https_proxy:
            cortex_api = Api(
                info.cortex_url,
                info.cortex_api,
                proxies={"http": info.http_proxy, "https": info.https_proxy},
                verify_cert=False,
            )
        else:
            cortex_api = Api(info.cortex_url, info.cortex_api, verify_cert=False)

        try:
            cortex_analyzers = [
                (x.name, x.dataTypeList)
                for x in cortex_api.analyzers.find_all({}, range="all")
                if len(set(x.dataTypeList).intersection(("url", "ip", "file", "mail")))
                > 0
            ]
        except (
            cortex4py.exceptions.AuthenticationError,
            cortex4py.exceptions.AuthorizationError,
            cortex4py.exceptions.ServiceUnavailableError,
            cortex4py.exceptions.CortexError,
        ):
            self.stdout.write(
                self.style.ERROR("Problems during cortex connection - Exit!")
            )
            sys.exit()

        if len(cortex_analyzers) > 0:
            self.stdout.write(
                self.style.SUCCESS(
                    "Cortex Analyzers: {}".format(
                        ", ".join([x[0] for x in cortex_analyzers])
                    )
                )
            )
        else:
            self.stdout.write(self.style.ERROR("No analyzers in cortex"))

        for analyzer in analyzers:
            if analyzer.name not in [x[0] for x in cortex_analyzers]:
                analyzer.disabled = True
                analyzer.save()
                self.stdout.write(
                    self.style.ERROR("Disabled {}, not in cortex".format(analyzer))
                )

        for analyzer, supported_types in cortex_analyzers:
            if analyzer not in analyzers_name:
                new = Analyzer(
                    name=analyzer,
                    disabled=True,
                    supported_types=[
                        x for x in supported_types if x in ("url", "ip", "file", "mail")
                    ],
                )
                new.save()
                self.stdout.write(
                    self.style.SUCCESS("Created {} from cortex".format(analyzer))
                )
