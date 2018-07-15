from rest_framework.views import APIView
from rest_framework.response import Response


class SimpleAPI(APIView):

    def get(self, request, format=None):
        """
        Return a list of all users.
        """
        return Response('hidden')
